package main

import (
	"crypto/tls"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/ldap.v2"
)

func main() {
	conn, err := ldap.DialTLS("tcp", "ldap.chalmers.se:636", &tls.Config{
		ServerName: "ldap.chalmers.se",
		InsecureSkipVerify: true,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	//s_studier_forvantade_programdeltagare_chalmers_tkite_h21
	//s_passer_prog_tkite_h18
	//s_studier_programdeltagare_chalmers_mpdsc_h21
	//s_studier_programdeltagare_chalmers_tkite_h21

	//printMemerships(conn, "s_studier_forvantade_programdeltagare_chalmers_mpcas_h21", "s_studier_programdeltagare_*")
	/*for _, cid := range getMembersInGroup(conn, "s_studier_kursdeltagare_chalmers_dat405_h21") {
		fmt.Println(getUserFullName(conn, cid))
	}*/
	//printMemerships(conn, "s_studier_programdeltagare_chalmers_tkite_h18", "s_studier_forvantade_programdeltagare_*")
}

func getCids(conn *ldap.Conn, fullName string) []string {
	req := ldap.NewSearchRequest(
		"ou=people,dc=chalmers,dc=se",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0,0,false,
		fmt.Sprintf("(cn=%s)", fullName),
		[]string{"uid"}, nil)
	
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) <= 0 {
		fmt.Println(err)
		return []string{}
	}
	
	cids := []string{}
	for _, entry := range res.Entries {
		cids = append(cids, entry.GetAttributeValue("uid"))
	}

	return cids
}

func printMemerships(conn *ldap.Conn, group string, memberFilter string) {
	groupCount := map[string]int{}
	groupCount["None"] = 0
	members := getMembersInGroup(conn, group)
	members_n := float64(len(members))

	for _, cid := range members {
		//fmt.Println(getUserFullName(conn,cid))
		memberOf := getGroupsByMember(conn, memberFilter, cid)
		if len(memberOf) == 0 {
			groupCount["None"] += 1
			continue
		}
		for _, cn := range memberOf {
			if val, exist := groupCount[cn]; !exist {
				groupCount[cn] = 1
			} else {
				groupCount[cn] = val + 1
			}
		}
	}

	output := []string{}

	for name, count := range groupCount {
		output = append(output, fmt.Sprintf("%s: %d (%.2f %%)", strings.TrimPrefix(name, strings.ReplaceAll(memberFilter, "*", "")), count, (float64(count) / members_n) * 100))
	}

	sort.Strings(output)
	for _, s := range output {
		fmt.Println(s)
	}

	fmt.Printf("Total number of members: %.0f\n", members_n)
	
}

func getUserFullName(conn *ldap.Conn, cid string) string {
	req := ldap.NewSearchRequest(
		"ou=people,dc=chalmers,dc=se",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0,0,false,
		fmt.Sprintf("(uid=%s)", cid),
		[]string{"cn"}, nil)
	
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) <= 0 {
		fmt.Println(err)
		return ""
	}
	
	return res.Entries[0].GetAttributeValue("cn")
}

func getGroupsByMember(conn *ldap.Conn, groupPattern string, cid string) []string {
	req := ldap.NewSearchRequest(
		"ou=groups,dc=chalmers,dc=se",
	ldap.ScopeWholeSubtree,
	ldap.NeverDerefAliases, 10000,0,false,
	fmt.Sprintf("(&(cn=%s)(memberUid=%s))", groupPattern, cid), []string{"cn"}, nil)
	
	res, err := conn.Search(req)
	if err != nil {
		return []string{}
	}

	groups := []string{}
	for _,group := range res.Entries {
		groups = append(groups, group.GetAttributeValue("cn"))
	}

	return groups
}

func getGroups(conn *ldap.Conn, groupPattern string) []string {
	req := ldap.NewSearchRequest(
		"ou=groups,dc=chalmers,dc=se",
	ldap.ScopeWholeSubtree,
	ldap.NeverDerefAliases, 10000,0,false,
	fmt.Sprintf("(cn=%s)", groupPattern), []string{"cn"}, nil)
	
	res, err := conn.Search(req)
	if err != nil {
		return []string{}
	}

	groups := []string{}
	for _,group := range res.Entries {
		groups = append(groups, group.GetAttributeValue("cn"))
	}

	return groups
}

func getMembersInGroup(conn *ldap.Conn, groupPattern string) []string {
	req := ldap.NewSearchRequest(
		"ou=groups,dc=chalmers,dc=se",
	ldap.ScopeWholeSubtree,
	ldap.NeverDerefAliases, 10000,0,false,
	fmt.Sprintf("(cn=%s)", groupPattern), []string{"cn", "memberUid"}, nil)
	
	res, err := conn.Search(req)
	if err != nil {
		fmt.Println(err)
		return []string{}
	}

	members := []string{}
	for _,group := range res.Entries {
		members = append(members, group.GetAttributeValues("memberUid")...)
	}

	return members
}

func printUserAttributes(conn *ldap.Conn, cid string) {
	req := ldap.NewSearchRequest(
		"ou=people,dc=chalmers,dc=se",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0,0,false,
		fmt.Sprintf("(uid=%s)", cid),
		[]string{"*"}, nil)
	
	res, err := conn.Search(req)
	if err != nil {
		fmt.Println(err)
		return
	}

	if len(res.Entries) < 1 {
		fmt.Println("No entries found")
		return
	}
	
	 for _,attr := range res.Entries[0].Attributes {
		 fmt.Println(attr.Name, attr.Values)
	 }
}