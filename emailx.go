package emailx

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	//ErrInvalidFormat returns when email's format is invalid
	ErrInvalidFormat = errors.New("invalid format")
	//ErrUnresolvableHost returns when validator couldn't resolve email's host
	ErrUnresolvableHost = errors.New("unresolvable host")
	//ErrBlockedIPRange returns when the hostname resolved, but the IP is in a blocked range
	ErrBlockedIPRange = errors.New("blocked ip range")

	//BlockedIPs contains IP ranges to be considered invalid.
	//Initialized with the known private IP ranges
	BlockedIPs []*net.IPNet

	userRegexp = regexp.MustCompile("^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+$")
	hostRegexp = regexp.MustCompile("^[^\\s]+\\.[^\\s]+$")
	// As per RFC 5332 secion 3.2.3: https://tools.ietf.org/html/rfc5322#section-3.2.3
	// Dots are not allowed in the beginning, end or in occurances of more than 1 in the email address
	userDotRegexp = regexp.MustCompile("(^[.]{1})|([.]{1}$)|([.]{2,})")
)

var privateIPBlocks []*net.IPNet

// init prepares the IP default address ranges for IP blocking.
// Adapted from https://stackoverflow.com/questions/41240761/go-check-if-ip-address-is-in-private-network-space
func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
	BlockedIPs = append(BlockedIPs, privateIPBlocks...)
}

// Validate checks format of a given email and resolves its host name.
func Validate(email string) error {
	if len(email) < 6 || len(email) > 254 {
		return ErrInvalidFormat
	}

	at := strings.LastIndex(email, "@")
	if at <= 0 || at > len(email)-3 {
		return ErrInvalidFormat
	}

	user := email[:at]
	host := email[at+1:]

	if len(user) > 64 {
		return ErrInvalidFormat
	}
	if userDotRegexp.MatchString(user) || !userRegexp.MatchString(user) || !hostRegexp.MatchString(host) {
		return ErrInvalidFormat
	}

	// Look for MX records
	mxes, err := net.LookupMX(host)
	if err != nil || len(mxes) == 0 {
		// No MX records available, or lookup failed.
		// Fall back to A/AAAA records

		resolvedIPs, err := net.LookupIP(host)
		if err != nil || len(resolvedIPs) == 0 {
			// Only fail if both MX and A records are missing - any of the
			// two is enough for an email to be deliverable
			return ErrUnresolvableHost
		}
		if IsAnyIPBlocked(resolvedIPs) {
			return ErrBlockedIPRange
		}
		// Record resolved successfully, and is not in a blocked IP range
		return nil
	}

	// MX records found, validate them
	for _, mx := range mxes {
		// Check that at least one MX entry is valid and not in a blocked IP range.
		// net.LookupMX returns entries sorted by their preference, so we technically only validate the preferred server.
		if resolvedIP, err := net.LookupIP(mx.Host); err == nil && len(resolvedIP) > 0 {
			// MX hostname resolved successfully, ...
			if IsAnyIPBlocked(resolvedIP) {
				return ErrBlockedIPRange
			}
			// ... and is not in a blocked IP range
			return nil
		}
	}

	return ErrUnresolvableHost
}

// IsAnyIPBlocked returns true if any of the IP addresses in the given slice are loopback, unicast, multicast or in a blocked range.
// See also IsBlockedIP() and BlockedIPs.
func IsAnyIPBlocked(ips []net.IP) bool {
	for _, ip := range ips {
		if IsBlockedIP(ip) {
			return true
		}
	}
	return false
}

// IsBlockedIP returns true the given IP address is loopback, unicast, multicast or in a blocked range.
// See also IsAnyIPBlocked() and BlockedIPs.
func IsBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range BlockedIPs {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateFast checks format of a given email.
func ValidateFast(email string) error {
	if len(email) < 6 || len(email) > 254 {
		return ErrInvalidFormat
	}

	at := strings.LastIndex(email, "@")
	if at <= 0 || at > len(email)-3 {
		return ErrInvalidFormat
	}

	user := email[:at]
	host := email[at+1:]

	if len(user) > 64 {
		return ErrInvalidFormat
	}
	if userDotRegexp.MatchString(user) || !userRegexp.MatchString(user) || !hostRegexp.MatchString(host) {
		return ErrInvalidFormat
	}

	return nil
}

// Normalize normalizes email address.
func Normalize(email string) string {
	// Trim whitespaces.
	email = strings.TrimSpace(email)

	// Trim extra dot in hostname.
	email = strings.TrimRight(email, ".")

	// Lowercase.
	email = strings.ToLower(email)

	return email
}
