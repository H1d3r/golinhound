package golinhound

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

type LinhoundObject interface {
	GetComputer() Computer
	GetUserName() string
}

type LinhoundKey interface {
	GetPublicKey() PublicKey
}

type Computer struct {
	UniqueId string
	FQDN     string
	RootName string
}

func NewComputer(uniqueId string, fqdn string, rootName string) *Computer {
	return &Computer{uniqueId, fqdn, rootName}
}

type Sudoer struct {
	Computer         Computer
	UserName         string
	PasswordRequired bool
	Commands         string
}

func (s Sudoer) GetComputer() Computer {
	return s.Computer
}

func (s Sudoer) GetUserName() string {
	return s.UserName
}

func newSudoer(computer Computer, userName string, passwordRequired bool, commands string) *Sudoer {
	return &Sudoer{computer, userName, passwordRequired, commands}
}

type PublicKey struct {
	Base64            string
	Comment           string
	Algorithm         string
	FingerprintSHA256 string
	FingerprintMD5    string
	FIDO2             bool
}

func NewPublicKey(keyB64 string, comment string) (*PublicKey, error) {
	publicKey := PublicKey{Base64: keyB64, Comment: comment}

	// convert key to bytes and check validity
	keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] invalid base64 encoding in public key: %s", keyB64)
	}

	// compute additional PublicKey attributes
	publicKey.Algorithm = parseAlgorithm(keyBytes)
	publicKey.FingerprintSHA256 = parseFingerprintSHA256(keyBytes)
	publicKey.FingerprintMD5 = parseFingerprintMD5(keyBytes)
	publicKey.FIDO2 = parseFIDO2(keyBytes)

	return &publicKey, nil
}

func parseAlgorithm(keyBytes []byte) string {
	algLen := binary.BigEndian.Uint32(keyBytes[:4])
	return string(keyBytes[4 : 4+algLen])
}

func parseFingerprintSHA256(keyBytes []byte) string {
	hash := sha256.Sum256(keyBytes)
	hashB64 := base64.StdEncoding.EncodeToString(hash[:])
	fingerprint := strings.TrimRight(hashB64, "=")
	return fingerprint
}

func parseFingerprintMD5(keyBytes []byte) string {
	hash := md5.Sum(keyBytes)
	hashHex := hex.EncodeToString(hash[:])

	// add colons for SSH fingerprint notation
	var fingerprint string
	for i, c := range hashHex {
		if i != 0 && i%2 != 1 {
			fingerprint += ":"
		}
		fingerprint += string(c)
	}

	return fingerprint
}

func parseFIDO2(keyBytes []byte) bool {
	algorithm := parseAlgorithm(keyBytes)
	return strings.HasPrefix(algorithm, "sk-")
}

type AuthorizedKey struct {
	Computer  Computer
	UserName  string
	PublicKey PublicKey
	FilePath  string
}

func (ak AuthorizedKey) GetComputer() Computer {
	return ak.Computer
}

func (ak AuthorizedKey) GetUserName() string {
	return ak.UserName
}

func (ak AuthorizedKey) GetPublicKey() PublicKey {
	return ak.PublicKey
}

func newAuthorizedKey(computer Computer, userName string, publicKey *PublicKey, filePath string) *AuthorizedKey {
	return &AuthorizedKey{computer, userName, *publicKey, filePath}
}

type PrivateKey struct {
	Computer  Computer
	UserName  string
	PublicKey PublicKey
	FilePath  string
	KeyFormat string
	KDF       string
	Cipher    string
	Encrypted bool
}

func (pk PrivateKey) GetComputer() Computer {
	return pk.Computer
}

func (pk PrivateKey) GetUserName() string {
	return pk.UserName
}

func (pk PrivateKey) GetPublicKey() PublicKey {
	return pk.PublicKey
}

func NewPrivateKey(computer Computer, userName string, publicKey PublicKey, filePath string, keyFormat string, kdf string, cipher string) *PrivateKey {
	kdf = normalizeAlgorithms(kdf)
	cipher = normalizeAlgorithms(cipher)
	privateKey := PrivateKey{
		Computer:  computer,
		UserName:  userName,
		PublicKey: publicKey,
		FilePath:  filePath,
		KeyFormat: keyFormat,
		KDF:       kdf,
		Cipher:    cipher,
	}
	privateKey.Encrypted = (cipher != "none")
	return &privateKey
}

// normalizeAlgorithms takes algorithm strings with different formats and normalizes them
func normalizeAlgorithms(algorithm string) string {
	// unencrypted should be none
	if algorithm == "" {
		return "none"
	}

	// normalize
	algorithm = strings.ToLower(algorithm)
	algorithm = strings.ReplaceAll(algorithm, "aes-", "aes")
	algorithm = strings.ReplaceAll(algorithm, "aes128_", "aes128-")
	algorithm = strings.ReplaceAll(algorithm, "aes256_", "aes256-")

	return algorithm
}

type ForwardedKey struct {
	Computer        Computer
	UserName        string
	PublicKey       PublicKey
	LastLoginSocket string
	LastLoginTime   string
	LastLoginIP     string
}

func (fk ForwardedKey) GetComputer() Computer {
	return fk.Computer
}

func (fk ForwardedKey) GetUserName() string {
	return fk.UserName
}

func (fk ForwardedKey) GetPublicKey() PublicKey {
	return fk.PublicKey
}

func NewForwardedKey(computer Computer, userName string, publicKey PublicKey, lastLoginSocket string, lastLoginTime string, lastLoginIP string) *ForwardedKey {
	return &ForwardedKey{computer, userName, publicKey, lastLoginSocket, lastLoginTime, lastLoginIP}
}

type Keytab struct {
	Computer        Computer
	FilePath        string
	ClientPrincipal string
	ClientRealm     string
}

type TGT struct {
	Computer        Computer
	FilePath        string
	ClientPrincipal string
	ClientRealm     string
	StartTime       string
	EndTime         string
	RenewTime       string
}

type metadataInstanceCompute struct {
	ResourceId string `json:"resourceId"`
	Name       string `json:"name"`
	OSType     string `json:"osType"`
}

type metadataIdentityInfo struct {
	TenantId string `json:"tenantId"`
}

type AZVM struct {
	Computer        Computer
	TenantId        string
	ResourceId      string
	Name            string
	OperatingSystem string
}
