package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	//"fmt"

	"github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)
// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

var configBlockSize = 4096 //Do not modify this variable

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

func equal(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i, v := range a {
        if v != b[i] {
            return false
        }
    }
    return true
}

//User : User structure used to store the user information
//JSON Marshalling -- converting JSON object struct vals and data into byte array
//JSON UnMarshalling -- converting byte array rep'n of structure into struct object
type User struct {
	Username      string
	Password      string
	RSAPrivateKey *userlib.PrivateKey
	//UsernameHMAC  []byte
	UserHMAC []byte
	FileMetaData  map[string]map[string][]byte //key--FileName, value--INDEX
	//RSAPrivateKeyHMAC string
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}
type Gen struct {
	Name string
	Pswd string
}

type IndexArr struct {
	Indices []int
}

//32 byte HMAC
func computeHMAC(key []byte, data []byte) (hmac []byte, err error) {
	//fmt.Println("Inside computeHMAC: key: ",key, "data: ", data)
	HmacInit := userlib.NewHMAC(key)
	HmacInit.Write([]byte(data))
	HmacResult := HmacInit.Sum(nil)
	return HmacResult, nil
}

func symmEncrypt(key []byte, value []byte) (cipherResult []byte, err error) {
	// ciphertext := make([]byte, userlib.BlockSize+len(value))
	ciphertext := make([]byte, userlib.BlockSize+len(value))
	iv := ciphertext[:userlib.BlockSize]
	// Load random data
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	//iv := make([]byte, userlib.BlockSize) //CREATING AN IV BYTE OF ZEROS SINCE THE KEY IS STRONG ENOUGH
	// iv:=key
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], value)
	return ciphertext, nil
}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	//fmt.Println("data being stored: ",string(data))
	//noOfBlocks := (binary.Size(data))/configBlockSize
	fileNmHmac := userlib.NewHMAC([]byte(userdata.Username))
	fileNmHmac.Write([]byte(filename))
	fileNameHMAC := fileNmHmac.Sum(nil)

	filemetadata := userdata.FileMetaData
	filedata := filemetadata[string(fileNameHMAC)]
	var secret, hash, val []byte
	var isExists bool
	if(filedata==nil){
		secret = userlib.RandomBytes(16)
		hash = userlib.RandomBytes(16)
	}
	if(filedata != nil){
		// return errors.New("There is no such file")
		secret=filedata["secret"]
		hash=filedata["hash"] 
		val=filedata["isOwner"]
		filedata = nil
		isExists=true
	}
	

	length := len(data)
	configBlockLen := configBlockSize
	//fmt.Println("configBlockSize: ",configBlockLen)
	noOfDataBlocks := length / configBlockLen
	//fmt.Println("length of data: ",length)
	//fmt.Println("noOfDataBlocks: ",noOfDataBlocks)
	if length%configBlockLen != 0 {
		//fmt.Println("File data not a multiple of configBlockSize")
		return errors.New("File data not a multiple of configBlockSize")
	}

	//SECRET KEY GENERATION
	
	//fmt.Println("secret: ",secret)

	indexArr := make([]int, 0) //Creating index array to store block indices

	//assuming indexing of file block starts from 1.
	for blocknum := 0; blocknum <= noOfDataBlocks-1; blocknum++ {
		//fmt.Println("datablock : ")
		start := (blocknum) * configBlockLen
		end := (blocknum + 1) * configBlockLen
		blockData := data[start:end]
		// if blocknum == 1 {
		// 	//fmt.Println("data of blocknum - 1: ", string(blockData))
		// }

		blockHMAC, _ := computeHMAC(secret, data[start:end])
		//fmt.Println("blockHMAC len: ",len(blockHMAC))
		dataWithHMAC := append(blockData, blockHMAC...)
		dataBlockCipher, _ := symmEncrypt(secret, dataWithHMAC)
		//print("Cipher obtained: ",dataBlockCipher)
		//print("blockData len: ", len(blockData), " blockHMAC len: ", len(blockHMAC), " dataWithHMAC len: ",len(dataWithHMAC))
		blockNumHmac := userlib.NewHMAC(hash)//filename needs revisiting since two users may have same filename
		blockNumHmac.Write([]byte(string(blocknum)))
		blockNumberHMAC := blockNumHmac.Sum(nil)
		userlib.DatastoreSet(string(blockNumberHMAC), dataBlockCipher) //Setting datablock cipher against each index of block
		// fileBlock,_ := userlib.DatastoreGet(string(blocknum))
		// isSame := (len(fileBlock)==len(dataBlockCipher))
		// print("isSame: ",isSame)

		print("blocknum: ", blocknum)
		indexArr = append(indexArr, blocknum)

	}
	//CREATE INDEX FOR FILE Argon2Key(password []byte, salt []byte,keyLen uint32) []byte
	salt := userlib.RandomBytes(16)
	index := userlib.Argon2Key([]byte(filename), salt, 16)
	//print("index: ", index)

	indexComponent := IndexArr{indexArr}
	//fmt.Println("IN STORE FILE: ", indexComponent)

	indexCompJson, _ := json.Marshal(indexComponent)
	indexCompBytes := []byte(indexCompJson)

	indexFileHMAC, _ := computeHMAC(secret, indexCompBytes)
	//fmt.Println("indexFileHMAC length: ", len(indexFileHMAC))
	indexCompBytesWithHMAC := append(indexCompBytes, indexFileHMAC...)
	//fmt.Println("indexCompBytes length while insert: ", len(indexCompBytes))
	//fmt.Println("indexFileHMAC length while insert: ", len(indexFileHMAC))
	//fmt.Println("indexCompBytesWithHMAC length while insert: ", len(indexCompBytesWithHMAC))
	//ENCRYPTING AFTER BLOCK BYTES ARE APPENDED WITH HMAC
	indexFileCipher, _ := symmEncrypt(secret, indexCompBytesWithHMAC)

	userlib.DatastoreSet(string(index), indexFileCipher)
	//print("indexFileCipher: ",indexFileCipher)
	//Compute File name index to store file metadata against it
	//print("username: ",userdata.Username)
	// fileNameHMAC,_ := computeHMAC(userdata.Username,[]byte(filename))
	// fileNmHmac := userlib.NewHMAC([]byte(userdata.Username))
	// fileNmHmac.Write([]byte(filename))
	// fileNameHMAC := fileNmHmac.Sum(nil)

	// Computed filenameHMAC:{"INDEX":index,"secret":secret}
	//Need to set all the values to the user data structure

	fileData := make(map[string][]byte)
	//bit:=make([]byte,1)
	bit:= []byte("1")
	fileData["index"] = index
	fileData["secret"] = secret
	fileData["hash"] = hash
	if(!isExists){
		fileData["isOwner"] = bit
	}
	if(isExists){
		fileData["isOwner"] = val
	}

	fileMetaData := userdata.FileMetaData
	if(fileMetaData==nil){
		fileMetaData = make(map[string]map[string][]byte)
	}
	fileMetaData[string(fileNameHMAC)] = fileData
	// print("fileMetaData: ",fileMetaData)
	userdata.FileMetaData = fileMetaData
	// print("user file metadata: ",userdata.FileMetaData)

	userJson, _ := json.Marshal(userdata)

	//print("userJson: ",string(userJson))
	pswdLen := strings.Count(userdata.Password, "") - 1
	pswd := userdata.Password + strings.Repeat("0", 16-pswdLen) //IF PASSWORD LENGTH IS SHORTER THAN 16

	key := []byte(pswd)

	ciphertext := make([]byte, userlib.BlockSize+len(userJson))

	iv := make([]byte, userlib.BlockSize) //CREATING AN IV BYTE OF ZEROS SINCE THE KEY IS STRONG ENOUGH

	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], []byte(userJson))

	//fmt.Println("Usernamehmac: ", string(Usernamehmac))
	hashKey := strings.Repeat("7",16)
	UserNmHmac := userlib.NewHMAC([]byte(hashKey))
	UserNmHmac.Write([]byte(userdata.Username))
	Usernamehmac := UserNmHmac.Sum(nil)
	userlib.DatastoreSet(string(Usernamehmac), ciphertext)

	return nil

}

func symmDecrypt(secret []byte, indexFileBytes []byte) (clearData []byte, err error) {
	//iv := make([]byte, userlib.BlockSize) //CREATING AN IV BYTE OF ZEROS SINCE THE KEY IS STRONG ENOUGH
	// iv:=secret
	iv := indexFileBytes[:userlib.BlockSize]
	cipher := userlib.CFBDecrypter(secret, iv)

	cipher.XORKeyStream(indexFileBytes[userlib.BlockSize:], indexFileBytes[userlib.BlockSize:])

	clearData = indexFileBytes[userlib.BlockSize:]
	// print("clear data string: ",str)
	return clearData, nil
}

//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	if (len(data) % configBlockSize) != 0 {
		return errors.New("Data not a multiple of blockSize")
	}
	fileNmHmac := userlib.NewHMAC([]byte(userdata.Username))
	fileNmHmac.Write([]byte(filename))
	fileNameHMAC := fileNmHmac.Sum(nil)

	filemetadata := userdata.FileMetaData
	filedata := filemetadata[string(fileNameHMAC)]
	if filedata == nil {
		return errors.New("There is no such file")
	}
	index := filedata["index"]
	secret := filedata["secret"]
	hash := filedata["hash"]
	//print("len of index: ",len(index))
	indexFileBytes, _ := userlib.DatastoreGet(string(index))

	indexFileWithHMAC, _ := symmDecrypt(secret, indexFileBytes)
	// fmt.Println("")
	indexFileContent := indexFileWithHMAC[0 : len(indexFileWithHMAC)-32]

	//fmt.Println("indexFileWithHMAC len: ",len(indexFileWithHMAC))
	//fmt.Println("indexFileContent : ",string(indexFileContent))
	var arr IndexArr
	json.Unmarshal(indexFileContent, &arr)
	var indexArr []int
	indexArr = arr.Indices
	prevLength := len(indexArr)
	//fmt.Println("arr len: ",len(indexArr))

	dataBlocks := len(data) / configBlockSize
	for blocknum := 0; blocknum < dataBlocks; blocknum++ {
		start := (blocknum) * configBlockSize
		end := (blocknum + 1) * configBlockSize
		blockData := data[start:end]
		// if blocknum==1{
		// fmt.Println("data of blocknum - 1: ",string(blockData))
		// }

		blockHMAC, _ := computeHMAC(secret, data[start:end])
		//fmt.Println("blockHMAC len: ",len(blockHMAC))
		dataWithHMAC := append(blockData, blockHMAC...)
		dataBlockCipher, _ := symmEncrypt(secret, dataWithHMAC)
		//print("Cipher obtained: ",dataBlockCipher)
		//print("blockData len: ", len(blockData), " blockHMAC len: ", len(blockHMAC), " dataWithHMAC len: ",len(dataWithHMAC))
		blockNumHmac := userlib.NewHMAC(hash)
		blockNumHmac.Write([]byte(string(prevLength + blocknum)))
		blockNumberHMAC := blockNumHmac.Sum(nil)
		userlib.DatastoreSet(string(blockNumberHMAC), dataBlockCipher) //Setting datablock cipher against each index of block
		// fileBlock,_ := userlib.DatastoreGet(string(blocknum))
		// isSame := (len(fileBlock)==len(dataBlockCipher))
		// print("isSame: ",isSame)

		//print("blocknum: ",prevLength+blocknum)
		//fmt.Println("New blocknum: ",prevLength+blocknum)
		indexArr = append(indexArr, prevLength+blocknum)

	}
	indexComponent := IndexArr{indexArr}
	//fmt.Println("Index comp: ", indexComponent)

	indexCompJson, _ := json.Marshal(indexComponent)
	indexCompBytes := []byte(indexCompJson)

	indexFileHMAC, _ := computeHMAC(secret, indexCompBytes)
	//fmt.Println("indexFileHMAC length: ", len(indexFileHMAC))
	indexCompBytesWithHMAC := append(indexCompBytes, indexFileHMAC...)
	//fmt.Println("indexCompBytes length while insert: ",len(indexCompBytes))
	//fmt.Println("indexFileHMAC length while insert: ",len(indexFileHMAC))
	//fmt.Println("indexCompBytesWithHMAC length while insert: ",len(indexCompBytesWithHMAC))
	//ENCRYPTING AFTER BLOCK BYTES ARE APPENDED WITH HMAC
	indexFileCipher, _ := symmEncrypt(secret, indexCompBytesWithHMAC)

	userlib.DatastoreSet(string(index), indexFileCipher)

	return nil

}

// LoadFile :This loads a block from a file in the Datastore
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {

	//First Compute the filename hmac with username+filename
	//Then pick the index val, then get the index 1 from the arr file
	//then get the encrypted block against the index,
	//decrypt it and then compute the hash of the data and compare the hash to see if it is corrupted
	//if not return it

	fileNmHmac := userlib.NewHMAC([]byte(userdata.Username))
	fileNmHmac.Write([]byte(filename))
	fileNameHMAC := fileNmHmac.Sum(nil)

	filemetadata := userdata.FileMetaData
	filedata := filemetadata[string(fileNameHMAC)]
	if filedata == nil {
		return nil, errors.New("There is no such file")
	}
	indexHMAC := filedata["index"]
	secret := filedata["secret"]
	hash := filedata["hash"]
	//print("len of indexHMAC: ",len(indexHMAC))
	indexFileBytes, _ := userlib.DatastoreGet(string(indexHMAC))
	//fmt.Println("******INDX FILE: ",indexFileBytes)
	if(indexFileBytes==nil || len(indexFileBytes)==0){
		return nil,errors.New("No access to file")
	}
	indexFileWithHMAC, _ := symmDecrypt(secret, indexFileBytes)
	// fmt.Println("")
	indexFileContent := indexFileWithHMAC[0 : len(indexFileWithHMAC)-32]

	//fmt.Println("indexFileWithHMAC len: ",len(indexFileWithHMAC))
	//fmt.Println("indexFileContent : ",string(indexFileContent))
	var indexArr IndexArr
	json.Unmarshal(indexFileContent, &indexArr)
	var arr []int
	arr = indexArr.Indices
	//fmt.Println("len arr: ", len(arr), offset)
	if offset >= len(arr) {
		return nil, errors.New("Not a valid Offset")
	}
	blockNumHmac := userlib.NewHMAC(hash)
	blockNumHmac.Write([]byte(string(offset)))
	blockNumberHMAC := blockNumHmac.Sum(nil)

	cipherdata, ok := userlib.DatastoreGet(string(blockNumberHMAC))
	if !ok {
		return nil, errors.New("No file with given offset")
	}
	//fmt.Println("finally data for offset given: ",cipherdata)

	data, err = symmDecrypt(secret, cipherdata)
	data = data[0 : len(data)-32]
	//fmt.Println("finally clear data for offset given: ", string(data))
	return data, err

}

type sharingRecord struct {
	IndexHMAC []byte
	Secret    []byte
	Hash     []byte
	IsOwner []byte
}
type encryptRecord struct {
	Bytes []byte
	Sign   []byte
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	//return "", nil
	//get the file data
	// fileNmHmac := userlib.NewHMAC([]byte(userdata.Username))
	// fileNmHmac.Write([]byte(filename))
	// fileNameHMAC := fileNmHmac.Sum(nil)

	// filemetadata := userdata.FileMetaData
	// filedata := filemetadata[string(fileNameHMAC)]
	// if filedata == nil {
	// 	return " ", errors.New("There is no such file")
	// }
	hashKey := strings.Repeat("7",16)
	UserNmHmac := userlib.NewHMAC([]byte(hashKey))
	UserNmHmac.Write([]byte(recipient))
	Usernamehmac := UserNmHmac.Sum(nil)
	user,ok := userlib.DatastoreGet(string(Usernamehmac))
	if !ok || user==nil{
		return "",errors.New("No such recipient")
	}

	fileNmHmac := userlib.NewHMAC([]byte(userdata.Username))
	fileNmHmac.Write([]byte(filename))
	fileNameHMAC := fileNmHmac.Sum(nil)

	filemetadata := userdata.FileMetaData
	filedata := filemetadata[string(fileNameHMAC)]
	//print("file data is",filedata)

	if filedata == nil {
		return " ", errors.New("-------There is no such weird file--------")
	}
	var sr sharingRecord 
	sr.IndexHMAC = filedata["index"]
	sr.Secret = filedata["secret"]
	sr.Hash = filedata["hash"]
	sr.IsOwner = []byte("0")

	//maintining integrity
	srJson, _ := json.Marshal(sr)
	//fmt.Println("user before MAC: ",string(srJson))
	// srHmac := userlib.NewHMAC(sr.secret)
	// srHmac.Write([]byte(srJson))
	// srhmac := srHmac.Sum(nil)

	// // encrypt the sharing record with sender private key
	// bytes, err := userlib.RSAEncrypt(userdata.RSAPrivateKey,[]byte(srJson),[]byte("Tag"))
	// if err != nil {
	// 	return " ", errors.New("error in encrytion")
	// }
	bytes:=[]byte(srJson)
	//sigining
	sign, err := userlib.RSASign(userdata.RSAPrivateKey, bytes)
	if err != nil {
		return " ", errors.New("error in signing")
	}
	//encrypting the encrypted record for confidentiality
	val, ok := userlib.KeystoreGet(recipient)
	//print("\n value",val)
	// if val!=nil {
	// 	return " ",errors.New("Got a key when I shouldn't")
	// }
	if !ok  {
		return " ", errors.New("error in public key retrieval")
	}
	//vihari:=append(bytes,sign...)
	//print("bytes==",bytes)
	

	
	// print("\n----before encryption byte array is -----",encBytes)

	Bytes, err := userlib.RSAEncrypt(&val,bytes,[]byte("Tag"))
	if err != nil {
		return " ", errors.New("error in encrytion2")
	}
	var enc encryptRecord
	enc.Bytes = Bytes
	enc.Sign = sign
	encJson, _ := json.Marshal(enc)
	encBytes:=[]byte(encJson)
	//encBytes=append(Bytes,sign)
	return string(encBytes),nil
}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) (err error) {
	
	encBytes:=[]byte(msgid)
	var enc encryptRecord
	//print("\n----decrypted value-----",decrypt)
	json.Unmarshal(encBytes, &enc)//[userlib.BlockSize:]
	//print("\n------unmarshalled data-----  ",enc.Bytes)
	bytes:=enc.Bytes
	sign:=enc.Sign
	// decrypting the encBytes with recievers private key
	//print("got encrypted bytes")
	decrypt, err := userlib.RSADecrypt(userdata.RSAPrivateKey,bytes, []byte("Tag"))
	if err != nil{
		return errors.New("error in decrytion2")
	}
	

	//bytes:=decrypt[0:len(decrypt)-256]
	//sign:=decrypt[len(bytes):]
	// decrypting the original msg
	val, ok := userlib.KeystoreGet(sender)
	if  !ok {
		return errors.New("no such sender")
	}
	err = userlib.RSAVerify(&val, decrypt, sign)
	if err != nil {
		return errors.New("RSA verification failed")
	}
	// orgMsg, err := RSADecrypt(&val,content, []byte("Tag"))
	// if err != nil{
	// 	t.Error("Decryption failure", err)
	// }
	//compute hash of the msg
	var sr sharingRecord
	json.Unmarshal(decrypt, &sr)
	// srJson, _ := json.Marshal(sr)
	// srHmac := userlib.NewHMAC(sr.secret)
	// srHmac.Write([]byte(srJson))
	// srhmac := srHmac.Sum(nil)
	// if(!equal(srhmac,orgsrhmac)){
	// 	return nil,errors.New("msg modified")
	// }
	//add file
	fileNmHmac := userlib.NewHMAC([]byte(userdata.Username))
	fileNmHmac.Write([]byte(filename))
	fileNameHMAC := fileNmHmac.Sum(nil)

	// Computed filenameHMAC:{"INDEX":index,"secret":secret}
	//Need to set all the values to the user data structure

	fileData := make(map[string][]byte)

	fileData["index"] = sr.IndexHMAC
	fileData["secret"] = sr.Secret
	fileData["hash"] = sr.Hash
	fileData["isOwner"] = sr.IsOwner
	//fileMetaData := userdata.FileMetaData

	if(userdata.FileMetaData==nil){
		userdata.FileMetaData=make(map[string]map[string][]byte)
	}

	userdata.FileMetaData[string(fileNameHMAC)] = fileData
	// print("fileMetaData: ",fileMetaData)
	// userdata.FileMetaData = fileMetaData //REVISIT TO USER MAC INCLUDING FILE META DA
	// print("user file metadata: ",userdata.FileMetaData)

	userJson, _ := json.Marshal(userdata)

	//print("userJson: ",string(userJson))
	pswdLen := strings.Count(userdata.Password, "") - 1
	pswd := userdata.Password + strings.Repeat("0", 16-pswdLen) //IF PASSWORD LENGTH IS SHORTER THAN 16

	key := []byte(pswd)

	// ciphertext := make([]byte, userlib.BlockSize+len(userJson))

	// iv := make([]byte, userlib.BlockSize) //CREATING AN IV BYTE OF ZEROS SINCE THE KEY IS STRONG ENOUGH
	ciphertext := make([]byte, userlib.BlockSize+len(userJson))
	iv := ciphertext[:userlib.BlockSize]
	// Load random data
	copy(iv, userlib.RandomBytes(userlib.BlockSize))

	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], []byte(userJson))

	//fmt.Println("Usernamehmac: ", string(Usernamehmac))
	hashKey := strings.Repeat("7",16)
	UserNmHmac := userlib.NewHMAC([]byte(hashKey))
	UserNmHmac.Write([]byte(userdata.Username))
	Usernamehmac := UserNmHmac.Sum(nil)
	userlib.DatastoreSet(string(Usernamehmac), ciphertext)
	return nil
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {


fileNmHmac := userlib.NewHMAC([]byte(userdata.Username))
fileNmHmac.Write([]byte(filename))
fileNameHMAC := fileNmHmac.Sum(nil)

filemetadata := userdata.FileMetaData
filedata := filemetadata[string(fileNameHMAC)]
//print("file data is",filedata)

if filedata == nil {
return errors.New("There is no such file")
}

indexHMAC := filedata["index"]
if string(filedata["isOwner"])=="0"{
	return errors.New("Cannot revoke!!")
}
//secret := userlib.RandomBytes(16)

indexFileBytes, _ := userlib.DatastoreGet(string(indexHMAC))

userlib.DatastoreSet(string(indexHMAC), nil)

salt := userlib.RandomBytes(16)
index := userlib.Argon2Key([]byte(filename), salt, 16)

userlib.DatastoreSet(string(index), indexFileBytes)
filedata["index"]=index
userdata.FileMetaData[string(fileNameHMAC)] = filedata
return nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
// type sharingRecord struct {
// }

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {
	if(len(username)==0 || len(password)==0){
		return nil,errors.New("Invalid user")
	}
	//Computing HMAC of Username
	hashKey := strings.Repeat("7",16)
	//fmt.Println("hashkey: ",hashKey)
	UserNmHmac := userlib.NewHMAC([]byte(hashKey))
	UserNmHmac.Write([]byte(username))
	Usernamehmac := UserNmHmac.Sum(nil)

	user1,_ := userlib.DatastoreGet(string(Usernamehmac))

	if(user1!=nil){
		return nil, errors.New("Username already exists")
	}
	RSAPrivateKey, _ := userlib.GenerateRSAKey()
	RSAPublicKey := RSAPrivateKey.PublicKey

	//Storing public key of user in keystore
	userlib.KeystoreSet(username, RSAPublicKey)

	
	

	user := User{Username: username, Password: password, RSAPrivateKey: RSAPrivateKey}//REMOVED USERNAMEHMAC
	
	userJson, _ := json.Marshal(user)
	//fmt.Println("user before MAC: ",string(userJson))
	UserHmac := userlib.NewHMAC([]byte(password))
	UserHmac.Write([]byte(userJson))
	Userhmac := UserHmac.Sum(nil)


	user.UserHMAC  = Userhmac
	userJson, _ = json.Marshal(user)

	//fmt.Println("userJson in init user: ",string(userJson))	
	pswdLen := strings.Count(password, "") - 1
	password = password + strings.Repeat("0", 16-pswdLen) //IF PASSWORD LENGTH IS SHORTER THAN 16

	key := []byte(password)

	// ciphertext := make([]byte, userlib.BlockSize+len(userJson))

	// iv := make([]byte, userlib.BlockSize) //CREATING AN IV BYTE OF ZEROS SINCE THE KEY IS STRONG ENOUGH
	ciphertext := make([]byte, userlib.BlockSize+len(userJson))
	iv := ciphertext[:userlib.BlockSize]
	// Load random data
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], []byte(userJson))

	//fmt.Println("Usernamehmac: ", string(Usernamehmac))
	userlib.DatastoreSet(string(Usernamehmac), ciphertext) //STORE ENCRYPTED USER DATA STRUCTURE AGAINST USRNAME HMAC

	//fmt.Println("dataStruct: ", ciphertext)

	//fmt.Println("usrRSA: ", *user.RSAPrivateKey)
	return &user, nil

}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {
	hashKey := strings.Repeat("7",16)
	UserNmHmac := userlib.NewHMAC([]byte(hashKey))
	UserNmHmac.Write([]byte(username))
	Usernamehmac := UserNmHmac.Sum(nil)

	//fmt.Println("Usernamehmac: ", string(Usernamehmac))

	dataStruct, ok := userlib.DatastoreGet(string(Usernamehmac))

	if ((!ok)||(dataStruct==nil)) {

		return nil, errors.New("username or password error")

	}
	//ciphertext := make([]byte, BlockSize+len(msg))
	iv := dataStruct[:userlib.BlockSize]
	// Load random data
	//copy(iv, RandomBytes(BlockSize))
	//iv := make([]byte, userlib.BlockSize) //CREATING AN IV BYTE OF ZEROS SINCE THE KEY IS STRONG ENOUGH
	passcode := password
	pswdLen := strings.Count(password, "") - 1
	password = password + strings.Repeat("0", 16-pswdLen) //IF PASSWORD LENGTH IS SHORTER THAN 16

	key := []byte(password)

	cipher := userlib.CFBDecrypter(key, iv)

	cipher.XORKeyStream(dataStruct[userlib.BlockSize:], dataStruct[userlib.BlockSize:])

	// str := string(dataStruct[userlib.BlockSize:])
	// str=""
	// fmt.Println("dataStruct string: ", str)

	var user1 User
	json.Unmarshal(dataStruct[userlib.BlockSize:], &user1)
	
	var actualHMAC []byte
	actualHMAC = user1.UserHMAC

	var actualMeta map[string]map[string][]byte
	actualMeta = user1.FileMetaData

	//fmt.Println("actualHMAC: ",actualHMAC)
	user1.UserHMAC = nil
	user1.FileMetaData = nil

	userJson,_ := json.Marshal(user1)

	UserHmac := userlib.NewHMAC([]byte(passcode))
	UserHmac.Write([]byte(userJson))
	Userhmac := UserHmac.Sum(nil)

	if(!equal(Userhmac, actualHMAC)){
		user1.UserHMAC = actualHMAC
		user1.FileMetaData = actualMeta
		return nil, errors.New("corrupted data")
	}


	user1.UserHMAC = actualHMAC
	user1.FileMetaData = actualMeta

	userJson,_ = json.Marshal(user1)
	//fmt.Println("before returning user: ",string(userJson))
	//fmt.Println("usrname: ", *user1.RSAPrivateKey)
	//fmt.Println("getUser returned: ",user1)
	return &user1, nil
}
