package hibp

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Lookup checks the supplied password against haveibeenpwned.com's range API
// and returns the number of times the password has been seen by
// haveibeenpwned. This works by sending the first 5 characters of the SHA-1
// hash of the password to the API and comparing the suffixes returned against
// the remainder of the hash.
func Lookup(password string) (int, error) {
	h := sha1.New()
	io.WriteString(h, password)
	hash := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))

	rangeURL := "https://api.pwnedpasswords.com/range/" + hash[:5]

	resp, err := http.Get(rangeURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	count := 0
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if count > 0 {
			continue
		}
		line := sc.Text()
		if len(line) > 35 && strings.HasPrefix(line, hash[5:]) {
			c, err := strconv.Atoi(line[36:])
			if err == nil {
				count = c
			}
		}
	}

	if err := sc.Err(); err != nil {
		return 0, err
	}

	return count, nil
}
