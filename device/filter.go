package device

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/sdp"
)

const (
	MAX_NUM_RULE_TOTAL         = 65535 //5
	MAX_NUM_RESOURCE_TOTAL     = 65535 //5
	MAX_NUM_RESOURCES_ONE_RULE = 8192  //4
	MAX_NUM_RULES_ONE_USER     = 1024  //5
)

type ParseError struct {
	why      string
	offender string
}

type Range struct {
	start uint16
	end   uint16
}
type ResourceItem struct {
	DstIP   net.IP
	DstPort uint16
}

type UserItem struct {
	SrcIP net.IP
}

type DstResource struct {
	AddrPort *netip.AddrPort
	Proto    uint8
	domains  map[string]interface{}
}

type IPResource struct {
	ipCidr     *netip.Prefix
	ports      []uint16
	portRanges []*Range

	bitLen  int
	proto   uint8
	ipRange struct {
		start *netip.Addr
		end   *netip.Addr
	}
	domain string
}

type IPResourceSet struct {
	id        string
	resources []*IPResource
}

type TimeRule struct {
	timeType int

	start int64
	end   int64

	startSecs int
	endSecs   int

	days []time.Weekday
}
type Rule struct {
	timeRule *TimeRule
	resIDs   []string
}

type HT struct {
	srcIP   string
	dipPort string
	//srcIP netip.Addr
	//AddrPort *netip.AddrPort //AddrPort 即资源ip 和端口
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s: %q", e.why, e.offender)
}
func myAddrIPtoString(ip netip.Addr) string {
	return fmt.Sprintf("%v", ip)
}
func myAddrPorttoString(addport netip.AddrPort) string {
	return fmt.Sprintf("%v", addport)
}

func parseIPCidr(s string) (netip.Prefix, error) {
	ipcidr, err := netip.ParsePrefix(s)
	if err == nil {
		return ipcidr, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, &ParseError{fmt.Sprintf("Invalid IP address: "), s}
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
func weekDayContains(days []time.Weekday, day time.Weekday) bool {
	for _, value := range days {
		if day == value {
			return true
		}
	}

	return false
}

func portContains(ports []uint16, port uint16) bool {
	for _, value := range ports {
		if value == port {
			return true
		}
	}
	return false
}
func (device *Device) filterPacket(packet []byte) bool {
	tuple, _ := sdp.ParseFiveTuple(packet)

	//device.log.Verbosef("sdp.ParseFiveTuple %v", tuple.String())

	now := time.Now()
	timestamp := now.Unix()
	weekDay := now.Weekday()
	secs := now.Hour()*3600 + now.Minute()*60 + now.Second()
	addr, _ := netip.AddrFromSlice(tuple.DstIP)
	addrPort := netip.AddrPortFrom(addr, tuple.DstPort)

	dst := &DstResource{
		&addrPort,
		0,
		nil,
	}
	var hot_item HT

	sip, _ := netip.AddrFromSlice(tuple.SrcIP)
	sip_string := myAddrIPtoString(sip)
	dip_string := myAddrPorttoString(addrPort)

	hot_item = HT{
		srcIP:   sip_string,
		dipPort: dip_string,
	}

	//fmt.Printf("sip=%v dest=%v \n", sip, addr)

	_, ok := device.hotTab.tabHandle[hot_item]
	if ok {
		//fmt.Printf("hit hot table")
		return true
	}

	var loop_count1 uint32
	var loop_count2 uint32
	loop_count1 = 0
	loop_count2 = 0
	for _, rule := range device.filter.rules {
		loop_count1++
		if filterRule(rule, device.filter.resources, timestamp, secs, weekDay, dst, &loop_count2) {
			if loop_count1 > 512 || loop_count2 > 1024 {
				device.hotTab.count++
				device.hotTab.tabHandle[hot_item] = device.hotTab.count
				//fmt.Printf("add hot table item[%v]=%v loop_count1=%d loop_count2=%d \n", hot_item, device.hotTab.count, loop_count1, loop_count2)
				//atomic.StoreUint32(&device.hotTab.count, uint32(deviceStateUp))
			}
			return true
		}
	}

	return false
}

func filterTime(rule *TimeRule, timestamp int64, secs int, day time.Weekday) bool {
	if timestamp < rule.start || timestamp > rule.end {
		return false
	}
	if rule.timeType == 1 && (secs < rule.startSecs || secs > rule.endSecs) {
		return false
	}
	if weekDayContains(rule.days, day) {
		return true
	}

	return false
}

func (r *Range) inRange(i uint16) bool {
	if i < r.start || i > r.end {
		return false
	}

	return true
}

func filterResource(resource *IPResource, dst *DstResource) bool {

	if resource.ipCidr != nil {
		if !resource.ipCidr.Contains(dst.AddrPort.Addr()) {
			//fmt.Printf("resource.ipCidr.Contains(dst.AddrPort.Addr()) return false resource.ipCidr:%v dst:%v ", resource.ipCidr, dst.AddrPort.Addr())
			return false
		}
	} else if dst.AddrPort.Addr().Compare(*resource.ipRange.start) == -1 || dst.AddrPort.Addr().Compare(*resource.ipRange.end) == 1 {
		return false
	}

	if resource.proto != 0 && dst.Proto != resource.proto {
		return false
	}
	if resource.portRanges == nil && resource.ports == nil {
		return true
	}
	dstPort := dst.AddrPort.Port()
	if resource.portRanges != nil {
		for _, portRange := range resource.portRanges {
			if portRange.inRange(dstPort) {
				return true
			}
		}
	}
	if resource.ports != nil && portContains(resource.ports, dstPort) {
		return true
	}

	return false
}

func filterRule(rule *Rule, resources map[string]*IPResourceSet, timestamp int64, secs int, weekDay time.Weekday, dst *DstResource, loop_count *uint32) bool {
	timeRule := rule.timeRule
	if timeRule != nil && !filterTime(timeRule, timestamp, secs, weekDay) {
		return false
	}

	for _, resID := range rule.resIDs {
		//fmt.Printf("resID:%v (index2:%v)\n", resID, index2)
		resSet := resources[resID]
		if resSet == nil {
			continue
		}
		for _, resource := range resSet.resources {
			//fmt.Printf("index:%v, ipCidr:%v , ports:%v \n", index, resource.ipCidr, resource.ports)
			*loop_count++
			if filterResource(resource, dst) {
				return true
			} else {
				continue
			}
		}
	}

	return false
}

func parsePort(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{fmt.Sprintf("Invalid port"), s}
	}
	return uint16(m), nil
}

func InetNtoA(ip int64) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func InetAtoN(ip string) int64 {
	ret := big.NewInt(0)
	ret.SetBytes(net.ParseIP(ip).To4())
	return ret.Int64()
}

func parseTimeRule(timeInfo map[string]interface{}) *TimeRule {
	var rule TimeRule
	timeType, ok := timeInfo["timeType"].(float64)
	if ok {
		rule.timeType = int(timeType)
	}
	startDate, _ := timeInfo["startDate"].(string)
	if !ok {
		return nil
	}
	endDate, ok := timeInfo["stopDate"].(string)
	if !ok {
		return nil
	}
	startTime, ok := timeInfo["startTime"].(string)
	if !ok {
		return nil
	}
	endTime, ok := timeInfo["endTime"].(string)
	if !ok {
		return nil
	}

	start, err := time.ParseInLocation("2006-01-02 15:04:05", startDate+" "+startTime, time.Local)
	if err != nil {
		return nil
	}

	end, err := time.ParseInLocation("2006-01-02 15:04:05", endDate+" "+endTime, time.Local)
	if err != nil {
		return nil
	}
	rule.start = start.Unix()
	rule.end = end.Unix()
	rule.startSecs = start.Hour()*3600 + start.Minute()*60 + start.Second()
	rule.endSecs = end.Hour()*3600 + end.Minute()*60 + end.Second()

	daysInfos, ok := timeInfo["days"].([]interface{})
	if ok {
		var days []time.Weekday
		for _, value := range daysInfos {
			dayInfo, ok := value.(string)
			if ok {
				day, err := strconv.Atoi(dayInfo)
				if err == nil {
					day = day % 7
					days = append(days, time.Weekday(day))
				}
			}
		}
		rule.days = days
	}

	return &rule
}
func (device *Device) FilterInit() {

	f, _ := os.Open("rule.json")
	defer f.Close()
	json_decoder := json.NewDecoder(f)
	var timeinfo map[string]interface{}
	json_decoder.Decode(&timeinfo)
	var timeRule *TimeRule
	timeRule = parseTimeRule(timeinfo)

	i := 0
	endIP := "172.16.30.165" //  "172.15.30.167" to "172.16.30.165" total =65535
	ipInt := InetAtoN(endIP)
	ipInt -= MAX_NUM_RESOURCE_TOTAL - 1

	// fmt.Printf( "ipCidr:%v ports: %v ",ipRc.ipCidr,ipRc.ports)
	var ipResources []*IPResource
	for i = 0; i < MAX_NUM_RESOURCE_TOTAL; i++ {
		var ipRc IPResource
		if cidr, err := parseIPCidr(InetNtoA(ipInt + int64(i))); err == nil {
			ipRc.ipCidr = &cidr
		}
		ipRc.ports = []uint16{22, 5201, 1000, 2000}
		ipResources = append(ipResources, &ipRc)
	}

	fmt.Printf("add resource from i:%v, ipCidr:%v , ports:%v \n ......        to i:%v, ipCidr:%v , ports:%v\n",
		0, ipResources[0].ipCidr, ipResources[0].ports,
		MAX_NUM_RESOURCE_TOTAL-1, ipResources[MAX_NUM_RESOURCE_TOTAL-1].ipCidr, ipResources[MAX_NUM_RESOURCE_TOTAL-1].ports)

	//var resources map[string]*IPResourceSet	构造两个资源集合 0 和 1 ；集合0  不命中 集合1 命中
	// 总的资源集合id 0~4/5 57342 ~ 65533/65535，集合0的资源id 0~3 集合1的资源id 1~4/5   57343 ~ 65534/65535
	resources := make(map[string]*IPResourceSet)
	start := 0
	if MAX_NUM_RESOURCE_TOTAL-MAX_NUM_RESOURCES_ONE_RULE-1 > 0 {
		start = MAX_NUM_RESOURCE_TOTAL - MAX_NUM_RESOURCES_ONE_RULE - 1
	}

	for i = 0; i < 2; i++ {
		var ipRs IPResourceSet
		var ipResourcesTmp []*IPResource
		ipResourcesTmp = ipResources[start+i : start+i+MAX_NUM_RESOURCES_ONE_RULE]
		//fmt.Printf("add resource Set[%d] from resource[%v] to resource[%v]\n", i, start+i, start+i+MAX_NUM_RESOURCES_ONE_RULE-1)
		ipRs.id = strconv.Itoa(i)
		ipRs.resources = ipResourcesTmp
		resources[ipRs.id] = &ipRs
	}

	//rules	id 从0~4 其中0~3 使用资源集合 0  规则4 使用资源集合1
	var rules []*Rule
	var ruleinfo1 Rule
	var ruleinfo2 Rule

	for i = 0; i < MAX_NUM_RULES_ONE_USER-1; i++ {
		ruleinfo1.timeRule = timeRule
		ruleinfo1.resIDs = []string{"0"}
		rules = append(rules, &ruleinfo1)
	}
	ruleinfo2.timeRule = timeRule
	ruleinfo2.resIDs = []string{"1"}
	rules = append(rules, &ruleinfo2)

	//	hotHashTabl := make(map[*HT]int)
	device.filter.rules = rules
	device.filter.resources = resources
	device.hotTab.tabHandle = make(map[HT]uint32)
	device.hotTab.count = 0
}
