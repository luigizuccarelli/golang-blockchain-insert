package handlers

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"lmzsoftware.com/luigizuccarelli/golang-blockchain-insert/pkg/connectors"
	"lmzsoftware.com/luigizuccarelli/golang-blockchain-insert/pkg/schema"
)

const (
	CONTENTTYPE     string = "Content-Type"
	APPLICATIONJSON string = "application/json"
)

// A Signer is can create signatures that verify against a public key.
type Signer interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(data []byte) ([]byte, error)
}

/*
// A Signer is can create signatures that verify against a public key.
type Unsigner interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Unsign(data []byte, sig []byte) error
}
*/

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

/*
// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPublicKey(path string) (Unsigner, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(data)
}

// parsePublicKey parses a PEM encoded private key.
func parsePublicKey(pemBytes []byte) (Unsigner, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newUnsignerFromKey(rawkey)
}
*/

// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPrivateKey(path string) (Signer, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePrivateKey(data)
}

// parsePublicKey parses a PEM encoded private key.
func parsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sshKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sshKey = &rsaPrivateKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

/*
func newUnsignerFromKey(k interface{}) (Unsigner, error) {
	var sshKey Unsigner
	switch t := k.(type) {
	case *rsa.PublicKey:
		sshKey = &rsaPublicKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}
*/

type rsaPublicKey struct {
	*rsa.PublicKey
}

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

// Sign signs data with rsa-sha256
func (r *rsaPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
}

/*
// Unsign encrypts data with rsa-sha256
func (r *rsaPublicKey) Unsign(message []byte, sig []byte) error {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, sig)
}
*/

// aes section
func Encrypt(key []byte, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func EncryptInsertToBlockChain(w http.ResponseWriter, r *http.Request, con connectors.Clients) {
	var response *schema.Response
	var data *schema.InputData
	addHeaders(w, r)
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		con.Error(fmt.Sprintf("EncryptInsertToBlockChain %v\n", err))
		response = &schema.Response{Name: os.Getenv("NAME"), StatusCode: "500", Status: "KO", Message: fmt.Sprintf("Could not read body data %v\n", err)}
		w.WriteHeader(http.StatusInternalServerError)
		b, _ := json.MarshalIndent(response, "", "	")
		fmt.Fprintf(w, string(b))
		return
	}

	data, err = encryptProcess(string(body), con)
	if err != nil {
		con.Error(fmt.Sprintf("EncryptInsertToBlockChain %v\n", err))
		response = &schema.Response{Name: os.Getenv("NAME"), StatusCode: "500", Status: "KO", Message: fmt.Sprintf("Could not read body data %v\n", err)}
		w.WriteHeader(http.StatusInternalServerError)
		b, _ := json.MarshalIndent(response, "", "	")
		fmt.Fprintf(w, string(b))
		return
	}

	// send to blockchain microservice
	block, _ := json.MarshalIndent(&data, "", "	")
	con.Debug(fmt.Sprintf("Data from encryptProcess : %v\n", data))
	req, err := http.NewRequest("POST", os.Getenv("URL"), bytes.NewBuffer(block))
	resp, err := con.Do(req)
	defer resp.Body.Close()
	if err != nil || resp.StatusCode != 200 {
		con.Error(fmt.Sprintf("Http request %v\n", err))
		response = &schema.Response{Name: os.Getenv("NAME"), StatusCode: "500", Status: "KO", Message: fmt.Sprintf("Http request error %v\n", err)}
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			response = &schema.Response{Name: os.Getenv("NAME"), StatusCode: "500", Status: "KO", Message: fmt.Sprintf("Could not read body data %v\n", err)}
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			response = &schema.Response{Name: os.Getenv("NAME"), StatusCode: "200", Status: "OK", Message: "EncryptInsertToBlockChain request processed succesfully" + string(body)}
			w.WriteHeader(http.StatusOK)
		}
	}
	b, _ := json.MarshalIndent(response, "", "	")
	con.Debug(fmt.Sprintf("EncryptInsertToBlockChain response : %s", string(b)))
	fmt.Fprintf(w, string(b))
}

func encryptProcess(msg string, con connectors.Clients) (*schema.InputData, error) {
	var data *schema.InputData

	// check msg is not empty
	if msg == "" {
		return data, errors.New("empty msg field")
	}

	signer, err := loadPrivateKey("../../keys/private.pem")
	if err != nil {
		con.Error(fmt.Sprintf("Private read file %v\n", err))
		return data, err
	}

	key := []byte("myverystrongpasswordo32bitlength")

	signed, err := signer.Sign([]byte(key))
	if err != nil {
		con.Error(fmt.Sprintf("Signing failed %v\n", err))
		return data, err
	}
	sig := base64.StdEncoding.EncodeToString(signed)
	con.Trace(fmt.Sprintf("Signature (ObjectA) %s\n", sig))

	plainText := []byte(msg)
	ct, err := Encrypt([]byte(key), plainText)
	if err != nil {
		con.Error(fmt.Sprintf("Reading public key %v\n", err))
		return data, err
	}
	con.Trace(fmt.Sprintf("AES encrypt (ObjectB) %s\n", hex.EncodeToString(ct)))

	d, err := ioutil.ReadFile("../../keys/receiver-public.pem")
	if err != nil {
		con.Error(fmt.Sprintf("Reading public key %v\n", err))
		return data, err
	}
	block, _ := pem.Decode(d)
	if block == nil {
		con.Error("No ssh key")
		return data, errors.New("No ssh key")
	}
	pubRsa, err := x509.ParsePKIXPublicKey(block.Bytes)
	encAesKey, err := EncryptWithPublicKey([]byte(key), pubRsa.(*rsa.PublicKey))
	if err != nil {
		return data, err
	}
	con.Trace(fmt.Sprintf("Encrypt AES key (ObjectC) %s\n", hex.EncodeToString(encAesKey)))

	data = &schema.InputData{MetaInfo: "Microservice Blockchain Insert", ObjectA: sig, ObjectB: hex.EncodeToString(ct), ObjectC: hex.EncodeToString(encAesKey)}
	return data, nil

}

func IsAlive(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "{ \"version\" : \"1.0.2\" , \"name\": \""+os.Getenv("NAME")+"\" }")
}

// headers (with cors) utility
func addHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(CONTENTTYPE, APPLICATIONJSON)
	// use this for cors
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}
