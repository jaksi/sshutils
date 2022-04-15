package sshutils_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaksi/sshutils"
	"golang.org/x/crypto/ssh"
)

const (
	rsaOpenSSHPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEArVzxd3S6JwU+cyQjTZDzyONiA69XFsbIG5vKEcS5zhF7G3XT4gna
++lbeZVLj5R+XNpSFqTk2zDR+Ho2acEMneTvlETRBoAjDycejsi5HyOjTumRquABtAyvk6
UJXrfBsdMkm8TXa4nmmiK5DvJJCJB7Kl3H5WA7rrrCwEJjUUNACinRJ4Vt3xoI0Wer2z6l
VC/WvJI5CyX8VnuROc6dkEFF/XBa9TcL8xhJ8sJhzVf8DPfFtWSkvr5ojfIX5qtLmuHf3u
qk6vozvkmI5viDyqapsmuZHP4geD8zIKWEyOKdB6RvdiYYFb/FO8lICUTy9jY+xuQI3dvA
ffSE+UP3LiuHILmBsKMt9bvMKvBWPxFo/bXjJZYqGwRdF9iaYuVKvvFZfBN5F/Z9WSPbX0
o2/8LTipuJw521KOwGTqk5Y83f00hPG9nV5TAkpYnCtPBZ55LgNLRWDpVbhMmZRL9QGztY
5qa+QDJ4N21qtmOVsY7zY9XWREwZ94OtuGGw+NkXAAAFkDGo7MoxqOzKAAAAB3NzaC1yc2
EAAAGBAK1c8Xd0uicFPnMkI02Q88jjYgOvVxbGyBubyhHEuc4Rext10+IJ2vvpW3mVS4+U
flzaUhak5Nsw0fh6NmnBDJ3k75RE0QaAIw8nHo7IuR8jo07pkargAbQMr5OlCV63wbHTJJ
vE12uJ5poiuQ7ySQiQeypdx+VgO666wsBCY1FDQAop0SeFbd8aCNFnq9s+pVQv1rySOQsl
/FZ7kTnOnZBBRf1wWvU3C/MYSfLCYc1X/Az3xbVkpL6+aI3yF+arS5rh397qpOr6M75JiO
b4g8qmqbJrmRz+IHg/MyClhMjinQekb3YmGBW/xTvJSAlE8vY2PsbkCN3bwH30hPlD9y4r
hyC5gbCjLfW7zCrwVj8RaP214yWWKhsEXRfYmmLlSr7xWXwTeRf2fVkj219KNv/C04qbic
OdtSjsBk6pOWPN39NITxvZ1eUwJKWJwrTwWeeS4DS0Vg6VW4TJmUS/UBs7WOamvkAyeDdt
arZjlbGO82PV1kRMGfeDrbhhsPjZFwAAAAMBAAEAAAGADZa4cqWapc5aa8oMXlsbUMbJ+w
H2cJmaO9fFSglCiy2BmdBtkE03dgF/oxMZviJkmUCfqJi6O5gjDTf/JeD07TdxtAyE2d6X
YOuvEIAZSqCPf3L9cQhn+cX4yTjpeBwtOZQUTYVrYUmI4tIP8WT6Zop0rQh2z7rwUqze8R
UDFe6QiXtnopJp30/6GvfmV6Qcb3HkghlwETikA99hrcdNQG5tXwU8i/YJoL9ppHaqFd9s
qVOOkr5Vz4G7Tk0IpJMOk+lCC/3cM1dNpSU02DUcMTichg/Qx4t+MFTVNCemvrwUQPbx/K
Haz5qQocdrFx1VdZRzgXjQedsUsE3KyzvaYD2cm+kFGhyWSXU7VjYF05DvKgSKVQ6Xmw+F
onlUlFK/s1AwMcMtnjq1ozlTY8lIrDBYG3BZD6YfoDt5LTKl/5eV9KpXuwihQreVtit5Oo
p8bOMGuOHAAM9U8N3O1bY6dNcLtkDwwLAnGBK7Pc9H6DCUyruH+YvYl8CQPMd8rPehAAAA
wQDk7fv6ncjsFa56xJbYOtlj3fklh4YR86nZidDttAb505N3mDFMGf0QSMYcD3Md0NbQYO
B6RFyO7VEeigiNtiJSD6V/GjKrIcx7A8xtvpCUNRU5PCMPhaMJCcFDnnrSnksWbYZ+yUpU
Uie1B9/icHNtdfzRwCiwjNZq/7WWXBfsri/28gOci4/UyEOWyx6iN3FX1VVZM5aGhtXyVu
sz2PPRkw8UTOIpIUlwL2AYpuio6nzGSGywQsxnAyfcRmThUTgAAADBAOXv08Y0LrQvtbRJ
y6Ydf9ufyTUE0sAk36feDd71+GhuPOQOuovH/PiRzivjOKBcDL8ehXxACtv6libTFfPxx4
gs7Ae96vjPVvM4/4PrU6Z4+xe2nk5ioWfPusEji/odMI30M3Z1Pz9wlsyKoyI6KvJjy639
Xl2jN9Uf8Ju5oen5Xp66uiIyPvIS2EM9deMeltWQTY/sNiVnGbKtODO2gUcBFV7vVFZPfX
p1lFhZQpzo8U7oYcjfscKoI0xkDtYahwAAAMEAwQN9znbDf1MwbKEBG3tc6/JoWuYo6t0N
yswDka1pEx7CqOHbNaAqF2FIbLznRDXdctlG4BQSmv5KnSyKujztHVlP680kcODtLxZFIV
huaJ3f7Bd4lsTeSIDlaosLCa5WMGV6C6ElsTyzRdXWdSSOWJIYqrX3LAL/YLMMJanpymIo
MDPcK4VjdAtJZ/hPHHxY53qLRdLLg1ofuVsJO3DBHwETeYfrzQmDLIGp/NZC9e0StfoHJC
wQUYEw86dyXyDxAAAAGWpha3NpQGpha3NpLW1hY2Jvb2subG9jYWwB
-----END OPENSSH PRIVATE KEY-----`
	rsaPrivateKey = `-----BEGIN PRIVATE KEY-----
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
zSxmjeSQNzd7TmJeHqaiuY3Q/Q==
-----END PRIVATE KEY-----`
	ecdsaOpenSSHPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQT3a3hG5vhvN6uJdGnDRjbr/8jyuJpL
OR45eVpwbXKodXj/edflVpQx43FDOrOeqo10tHvRpKwvtINiFn6O3y0sAAAAuKfF6Tqnxe
k6AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPdreEbm+G83q4l0
acNGNuv/yPK4mks5Hjl5WnBtcqh1eP951+VWlDHjcUM6s56qjXS0e9GkrC+0g2IWfo7fLS
wAAAAgKPOaFo6Bt+BPYPY4m5EuT+D5by3PGY8E0GpcAD5czygAAAAZamFrc2lAamFrc2kt
bWFjYm9vay5sb2NhbAECAwQFBgc=
-----END OPENSSH PRIVATE KEY-----`
	ecdsaPrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLBcn7f415R554V92
HOUbU1rNJn607nO/QFcE57nJzI2hRANCAARjN8vOhE871+6sw5zpr8zxOhiSqZaK
+c0UdI4TDanmdJLNdYMYSnVGq2C6aCQQxHh0v2G+qxxevUAz2kcN03kK
-----END PRIVATE KEY-----`
	ed25519OpenSSHPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDwHujzcdXteU9kMpXOEZil1goBl6JKV547jJQVASIPkAAAAKDMkdgQzJHY
EAAAAAtzc2gtZWQyNTUxOQAAACDwHujzcdXteU9kMpXOEZil1goBl6JKV547jJQVASIPkA
AAAECaZ+l1kJ0hvmAYBl8Rz8/2Wri1QoZ5eWZuyPIz6u0+DvAe6PNx1e15T2Qylc4RmKXW
CgGXokpXnjuMlBUBIg+QAAAAGWpha3NpQGpha3NpLW1hY2Jvb2subG9jYWwBAgME
-----END OPENSSH PRIVATE KEY-----`
	ed25519PrivateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDnCGl4N8JoHGU1dQiHJtjX1YVqZq/mrftJ1VhZb+sKw
-----END PRIVATE KEY-----`
	dsaPrivateKey = `-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQDeA5uDcxxtZfwAWtTnCl8dBakVPZzo0A4lAK7O7dvaRmt2BREO
m9HeotvN+NgsHglsqdSkKmhY3+4Px65VYePuwWM76D9xEPchrp5yfAAVBX1S+ET8
vMWkjghC4gQj7xYorff0cxWHygkp0XdTGLJTXpSFCP1+QgA3Tth3r47fgQIVAK3w
gBUDC5xhXUPdfcUMcvs4C7m1AoGBAMyIalFqf6qdYKfVaJTeux2PhKjXSmiKTARL
3xijCPoFPvAOZs3RwGzB2Y0FtcnqLbSZztb703q0SbXH99Hau8mzvIyWbfL+xdq/
ExOdJLUO/EtjUzZombMPx53F6+jihMT7owjvL2oJFeQJ/8Xz72yznbxp+6EIrUOl
G8cOd1TdAoGAZMeYLrWECUncPFBapKqjsCxmBYAj5ZhLjHcTVwU64jja0YwQsZOt
MpFntE1kUdh/VQ0geU0GRx2VoXVUiQCpeE7vzml2VDfSla/3wX+rTDC7oUscci3u
W9r8PDu4I7cP/Pn8KcNgpanC6UWvULFZDqxa9cK64ARbg7a9PS5E6HoCFACMURhd
1s88mIV1gL3nwCMY/t0I
-----END DSA PRIVATE KEY-----`
	invalidECDSAPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MGgCAQEEHHaWA9AzQ27yay5uoOjd78rf4w01H11anBwTR1KgBwYFK4EEACGhPAM6
AAQlqiMN83r4zoLZ9U7l4g60j6dcCBE++nGcL8dcNFfsIAtXXhkHrPsyEU+EjZhg
QL1PUqWTNRnyHA==
-----END EC PRIVATE KEY-----`
)

var (
	rsaHostKey, ecdsaHostKey, ed25519HostKey, dsaHostKey           *sshutils.HostKey
	rsaHostkeyRequestPayloadBytes, ecdsaHostkeyRequestPayloadBytes []byte
)

func init() {
	var err error
	rsaHostKey, err = sshutils.GenerateHostKey(sshutils.RSA)
	if err != nil {
		panic(err)
	}
	ecdsaHostKey, err = sshutils.GenerateHostKey(sshutils.ECDSA)
	if err != nil {
		panic(err)
	}
	ed25519HostKey, err = sshutils.GenerateHostKey(sshutils.Ed25519)
	if err != nil {
		panic(err)
	}
	dsaHostKeyFile := filepath.Join(os.TempDir(), "dsa_host_key")
	if err := ioutil.WriteFile(dsaHostKeyFile, []byte(dsaPrivateKey), 0o600); err != nil {
		panic(err)
	}
	defer os.Remove(dsaHostKeyFile)
	dsaHostKey, err = sshutils.LoadHostKey(dsaHostKeyFile)
	if err != nil {
		panic(err)
	}

	rsaHostkeyRequestPayloadBytes = ssh.Marshal(struct{ S string }{string(rsaHostKey.PublicKey().Marshal())})
	ecdsaHostkeyRequestPayloadBytes = ssh.Marshal(struct{ S string }{string(ecdsaHostKey.PublicKey().Marshal())})
}

func TestKeySignature(t *testing.T) {
	for i, testCase := range []struct {
		input          sshutils.KeyType
		expectedString string
	}{
		{sshutils.RSA, "rsa"},
		{sshutils.ECDSA, "ecdsa"},
		{sshutils.Ed25519, "ed25519"},
		{-1, "unknown"},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if testCase.input.String() != testCase.expectedString {
				t.Errorf("%v.String() = %v, want %v", testCase.input, testCase.input.String(), testCase.expectedString)
			}
		})
	}
}

func TestGenerateHostKey(t *testing.T) {
	for i, testCase := range []struct {
		input                 sshutils.KeyType
		expectedPublicKeyType string
		expectedError         bool
	}{
		{sshutils.RSA, "ssh-rsa", false},
		{sshutils.ECDSA, "ecdsa-sha2-nistp256", false},
		{sshutils.Ed25519, "ssh-ed25519", false},
		{-1, "", true},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			hostKey, err := sshutils.GenerateHostKey(testCase.input)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("GenerateHostKey(%v) = %v, want non-nil", testCase.input, err)
				}
			} else {
				if err != nil {
					t.Fatalf("GenerateHostKey(%v) = %v, want nil", testCase.input, err)
				}
				if hostKey.PublicKey().Type() != testCase.expectedPublicKeyType {
					t.Errorf("GenerateHostKey(%v).PublicKey().Type() = %v, want %v", testCase, hostKey.PublicKey().Type(), testCase.expectedPublicKeyType)
				}
				expectedPrefix := "SHA256:"
				if !strings.HasPrefix(hostKey.String(), expectedPrefix) {
					t.Errorf("GenerateHostKey(%v).String() = %v, want prefix %v", testCase, hostKey.String(), expectedPrefix)
				}
			}
		})
	}
}

func TestLoadHostKey(t *testing.T) {
	for i, testCase := range []struct {
		input                 []byte
		expectedPublicKeyType string
		expectedError         bool
	}{
		{[]byte(rsaOpenSSHPrivateKey), "ssh-rsa", false},
		{[]byte(rsaPrivateKey), "ssh-rsa", false},
		{[]byte(ecdsaOpenSSHPrivateKey), "ecdsa-sha2-nistp256", false},
		{[]byte(ecdsaPrivateKey), "ecdsa-sha2-nistp256", false},
		{[]byte(ed25519OpenSSHPrivateKey), "ssh-ed25519", false},
		{[]byte(ed25519PrivateKey), "ssh-ed25519", false},
		{[]byte(dsaPrivateKey), "ssh-dss", false},
		{[]byte(invalidECDSAPrivateKey), "", true},
		{[]byte("invalid"), "", true},
		{nil, "", true},
	} {
		i := i
		testCase := testCase
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			hostKeyFile := filepath.Join(t.TempDir(), fmt.Sprint("hostkey_", i))
			if testCase.input != nil {
				if err := ioutil.WriteFile(hostKeyFile, testCase.input, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			hostKey, err := sshutils.LoadHostKey(hostKeyFile)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("LoadHostKey(...) = %v, want non-nil", hostKey)
				}
			} else {
				if err != nil {
					t.Fatalf("LoadHostKey(...) = %v, want nil", err)
				}
				if hostKey.PublicKey().Type() != testCase.expectedPublicKeyType {
					t.Errorf("LoadHostKey(...).PublicKey().Type() = %v, want %v", hostKey.PublicKey().Type(), testCase.expectedPublicKeyType)
				}
			}
		})
	}
}

func TestSaveHostKey(t *testing.T) {
	hostKeyDirectory := t.TempDir()

	for i, testCase := range []struct {
		hostKey       *sshutils.HostKey
		file          string
		expectedError bool
	}{
		{rsaHostKey, filepath.Join(hostKeyDirectory, "rsa"), false},
		{ecdsaHostKey, filepath.Join(hostKeyDirectory, "ecdsa"), false},
		{ed25519HostKey, filepath.Join(hostKeyDirectory, "ed25519"), false},
		{rsaHostKey, filepath.Join(hostKeyDirectory, "keys", "rsa"), true},
		{dsaHostKey, filepath.Join(hostKeyDirectory, "dsa"), true},
		{rsaHostKey, filepath.Join(hostKeyDirectory, "rsa"), true},
		{rsaHostKey, hostKeyDirectory, true},
	} {
		testCase := testCase
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			err := testCase.hostKey.Save(testCase.file)
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Save(%v) = %v, want non-nil", testCase.file, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Save(%v) = %v, want nil", testCase.file, err)
				}
				hostKey, err := sshutils.LoadHostKey(testCase.file)
				if err != nil {
					t.Fatalf("LoadHostKey(%v) = %v, want nil", testCase.file, err)
				}
				if hostKey.String() != testCase.hostKey.String() {
					t.Errorf("LoadHostKey(%v).String() = %v, want %v", testCase.file, hostKey.String(), testCase.hostKey.String())
				}
			}
		})
	}
}
