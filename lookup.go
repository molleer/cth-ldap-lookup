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

	tkite_members := getMembersInGroup(conn, "s_studier_programdeltagare_chalmers_tkite")
	tkdat_members := getMembersInGroup(conn, "s_studier_programdeltagare_chalmers_tkdat")
	tkelt_members := getMembersInGroup(conn, "s_studier_programdeltagare_chalmers_tkelt")

	sort.Strings(tkite_members)
	sort.Strings(tkdat_members)
	sort.Strings(tkelt_members)
	
	fmt.Printf("%d IT members \n", len(tkite_members))
	fmt.Printf("%d Data members \n", len(tkdat_members))
	fmt.Printf("%d Electro members \n", len(tkelt_members))

	masters := map[string]string{
		"mpdsc": "MPDSC (IT)",
		"mpsof": "MPSOF (IT)",
		"mpide": "MPIDE (IT)",
		"mpalg": "MPALG (DAT)",
		"mpcsn": "MPCSN (DAT)",
		"mphpc": "MPHPC (DAT)",
		"mpbme": "MPBME (ELT)",
		"mpees": "MPEES (ELT)",
		"mpcom": "MPCOM (ELT)",
		"mpepo": "MPEPO (ELT)",
		"mpwps": "MPWPS (ELT)"};
	
	for k, v := range masters {
		master_students := getMembersInGroup(conn, fmt.Sprintf("s_passer_prog_%s", k))
		sort.Strings(master_students)
		
		fmt.Printf("\n%d %s members \n", len(master_students), v)
		fmt.Printf("- %d IT members \n", nOverlapp(master_students, tkite_members))
		fmt.Printf("- %d Data members \n", nOverlapp(master_students, tkdat_members))
		fmt.Printf("- %d Electro members \n", nOverlapp(master_students, tkelt_members))
	}
}

// Assuming a and b are soreted
func nOverlapp(a []string, b[]string) int {
	count := 0
	ai := 0
	bi := 0
	for ai < len(a) && bi < len(b) {
		if a[ai] > b[bi] {
			bi += 1
		} else if a[ai] < b[bi] {
			ai += 1
		} else {
			count += 1
			ai += 1
			bi += 1
		}
	}
	return count
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