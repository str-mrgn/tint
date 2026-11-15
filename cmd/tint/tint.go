package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"syscall"

	apipb "github.com/osrg/gobgp/v3/api"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type FlowspecRule struct {
	DstIP      string
	DstMask    uint32
	SrcIP      string
	SrcMask    uint32
	Protocol   uint32
	DstPort    uint32
	SrcPort    uint32
	CommonPort uint32
	Color      uint32
}

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect to GoBGP gRPC server: %v", err)
	}
	defer conn.Close()

	client := apipb.NewGobgpApiClient(conn)

	req := &apipb.WatchEventRequest{
		Table: &apipb.WatchEventRequest_Table{
			Filters: []*apipb.WatchEventRequest_Table_Filter{
				{
					Type: apipb.WatchEventRequest_Table_Filter_BEST,
					Init: true,
				},
			},
		},
	}

	stream, err := client.WatchEvent(context.Background(), req)
	if err != nil {
		log.Fatalf("Failed to start WatchEvent stream: %v", err)
	}

	fmt.Println("Started real-time monitoring of GoBGP Flowspec RIB...")

	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Stream receive error: %v", err)
		}

		tableEvent := res.GetTable()
		if tableEvent == nil {
			continue
		}

		for _, path := range tableEvent.GetPaths() {
			var fsNLRI apipb.FlowSpecNLRI
			if err := path.GetNlri().UnmarshalTo(&fsNLRI); err != nil {
				continue
			}

			var ruleData FlowspecRule

			for _, rule := range fsNLRI.GetRules() {
				var ipPrefix apipb.FlowSpecIPPrefix
				var comp apipb.FlowSpecComponent

				if err := rule.UnmarshalTo(&ipPrefix); err == nil {
					switch ipPrefix.GetType() {
					case 1:
						ruleData.DstIP = ipPrefix.GetPrefix()
						ruleData.DstMask = ipPrefix.GetPrefixLen()
					case 2:
						ruleData.SrcIP = ipPrefix.GetPrefix()
						ruleData.SrcMask = ipPrefix.GetPrefixLen()
					}
					continue
				}

				if err := rule.UnmarshalTo(&comp); err == nil {
					if len(comp.GetItems()) == 0 {
						continue
					}
					val := uint32(comp.GetItems()[0].GetValue())

					switch comp.GetType() {
					case 3:
						ruleData.Protocol = val
					case 4:
						ruleData.CommonPort = val
					case 5:
						ruleData.DstPort = val
					case 6:
						ruleData.SrcPort = val
					}
					continue
				}
			}

			if ruleData.DstPort == 0 && ruleData.CommonPort > 0 {
				ruleData.DstPort = ruleData.CommonPort
			}

			for _, pattr := range path.GetPattrs() {
				var extComms apipb.ExtendedCommunitiesAttribute
				if err := pattr.UnmarshalTo(&extComms); err == nil {
					for _, comm := range extComms.GetCommunities() {
						var colorExt apipb.ColorExtended
						if err := comm.UnmarshalTo(&colorExt); err == nil {
							ruleData.Color = colorExt.GetColor()
						}
					}
				}
			}

			if err := applyIpRule(ruleData); err != nil {
				log.Printf("[ERROR] Failed to apply ip rule: %v\n", err)
			}

			fmt.Println("--------------------------------------------------------------------------")
		}
	}
}

func sendSyslogAlert(message string) {
	sysLog, err := syslog.Dial("udp", "syslog:514", syslog.LOG_WARNING|syslog.LOG_DAEMON, "prism")
	if err != nil {
		fmt.Printf("[ERROR] Failed to connect to syslog server (%s): %v\n", err)
		return
	}
	defer sysLog.Close()

	if err := sysLog.Warning(message); err != nil {
		fmt.Printf("[ERROR] Failed to send syslog alert: %v\n", err)
	} else {
		fmt.Println("[SYSLOG SENT]:", message)
	}
}

func applyIpRule(data FlowspecRule) error {
	if data.Color == 0 {
		return nil
	}

	// Map BGP Color value directly to the corresponding Linux routing table ID
	targetTable := int(data.Color)
	fmt.Printf("[MAPPING] Color %d -> Table %d\n", data.Color, targetTable)

	// Verify whether an SRv6 Policy (route) exists in the target routing table
	routeFilter := &netlink.Route{Table: targetTable}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, routeFilter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("failed to list routes in table %d: %w", targetTable, err)
	}

	if len(routes) == 0 {
		errMsg := fmt.Sprintf("ALERT: No SR Policy found for Color %d (Table %d) (Flow: Dst=%s/%d, Dport=%d)",
			data.Color, targetTable, data.DstIP, data.DstMask, data.DstPort)
		fmt.Println("[WARN]", errMsg)
		sendSyslogAlert(errMsg)
		return nil
	}
	fmt.Printf("[VERIFIED] Found %d route(s) in Table %d.\n", len(routes), targetTable)

	// Build Linux Policy-Based Routing (PBR) rule
	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V4
	rule.Table = targetTable

	if data.DstIP != "" {
		_, dstNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", data.DstIP, data.DstMask))
		if err != nil {
			return fmt.Errorf("invalid destination prefix: %w", err)
		}
		rule.Dst = dstNet
	}

	if data.SrcIP != "" {
		_, srcNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", data.SrcIP, data.SrcMask))
		if err != nil {
			return fmt.Errorf("invalid source prefix: %w", err)
		}
		rule.Src = srcNet
	}

	if data.Protocol > 0 {
		rule.IPProto = int(data.Protocol)
	}

	if data.DstPort > 0 {
		rule.Dport = netlink.NewRulePortRange(uint16(data.DstPort), uint16(data.DstPort))
	}

	if data.SrcPort > 0 {
		rule.Sport = netlink.NewRulePortRange(uint16(data.SrcPort), uint16(data.SrcPort))
	}

	fmt.Printf("[APPLY PBR] ip rule add: Src=%s/%d Dst=%s/%d Proto=%d Sport=%d Dport=%d -> Table %d (Color %d)\n",
		data.SrcIP, data.SrcMask, data.DstIP, data.DstMask,
		data.Protocol, data.SrcPort, data.DstPort, rule.Table, data.Color)

	if err := netlink.RuleAdd(rule); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			fmt.Println("[SKIP] Identical ip rule already exists.")
		} else {
			return fmt.Errorf("failed to add ip rule: %w", err)
		}
	}

	return nil
}
