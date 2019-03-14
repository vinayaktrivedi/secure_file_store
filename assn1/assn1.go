package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
  // You neet to add with
  // go get github.com/fenilfadadu/CS628-assn1/userlib
  "github.com/fenilfadadu/CS628-assn1/userlib"

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

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
  for x := range ret {
    ret[x] = data[x]
  }
  return
}

// The structure definition for a user record
type User struct {
  Username string
  Password string
  Salt string
  Private_Key *userlib.PrivateKey
  Files map[string]string
  User_Key string
  // You can add other fields here if you want...
  // Note for JSON to marshal/unmarshal, the fields need to
  // be public (start with a capital letter)
}

// New Type Definitions

// This structure contains the data that will be finally stored in the datastore
type Persistent_user_data struct {
  Username string     // hashed
  Salt string         // plaintext
  Password string     // hashed
  Private_Key string  // encrypted
  Files string        // encrypted
  Hmac string
}

type File struct {
  Symlink string
  Number_of_appends int
  Hmac_check string
}

type Append struct {
  Data string
  Hmac_check string
}

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


// Helper Functions

// This function is responsible for calculating Sha256 hash of the input string
func getSha256(data string) string {
  h := userlib.NewSHA256()
  h.Write([]byte(data))
  return hex.EncodeToString(h.Sum(nil))
}

// This function is responsible for performing CFBEncryption
// It returns IV concatenated with encrypted data
func getCFBEncryptedData(data []byte, key []byte) string {
  plaintext := []byte(data)
  iv := userlib.RandomBytes(userlib.AESKeySize)
  ciphertext := append(iv, make([]byte, len(plaintext))...)

  stream := userlib.CFBEncrypter(key, iv)
  stream.XORKeyStream(ciphertext[userlib.AESKeySize:], plaintext)
  return hex.EncodeToString(ciphertext)
}

// This function is responsible for performing CFBDecryption
// It returns plaintext
func getCFBDecryptedData(data string, key []byte) []byte {
  ciphertext, _ := hex.DecodeString(data)
  iv := ciphertext[:userlib.AESKeySize]
  ciphertext = ciphertext[userlib.AESKeySize:]

  stream := userlib.CFBDecrypter(key, iv)
  stream.XORKeyStream(ciphertext, ciphertext)
  return ciphertext
}

// This function is responsible for calculating HMAC of input data based on key
func getHmac(data string, key []byte) string {
  h := userlib.NewHMAC(key)
  h.Write([]byte(data))
  return hex.EncodeToString(h.Sum(nil))
}


func change_user_struct_files(userdata *User){

  decoded_salt,_ := hex.DecodeString(userdata.Salt)
  encryption_key := userlib.Argon2Key([]byte(userdata.Password), decoded_salt, 32)

  var user_to_store Persistent_user_data

  user_to_store.Username = getSha256(userdata.Username)

  user_to_store.Password = getSha256(userdata.Password + userdata.Salt)
  user_to_store.Salt = userdata.Salt

  private_key, err := json.Marshal(userdata.Private_Key)
  if err != nil {
    return
  }
  user_to_store.Private_Key = getCFBEncryptedData(private_key, encryption_key)

  files, err := json.Marshal(userdata.Files)
  if err != nil {
    return
  }
  user_to_store.Files = getCFBEncryptedData(files, encryption_key)

  hmac_data := user_to_store.Username + "\n" + user_to_store.Password + "\n" + user_to_store.Salt +
               "\n" + user_to_store.Private_Key + "\n" + user_to_store.Files
  user_to_store.Hmac = getHmac(hmac_data, encryption_key)

  marshalled_user_struct, err := json.Marshal(user_to_store)
  if err != nil {
    return
  }
  userlib.DatastoreSet(userdata.User_Key, marshalled_user_struct)

}

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {

  var userdata User

  // Check if the key with username and password already exists
  // If exists then return an error
  // Store username and password in memory structure
  // It will be encrypted later when stored in persistant datastore
  userdata.Username = username
  userdata.Password = password

  // Salt is generated randomly and stored in plaintext
  userdata.Salt = hex.EncodeToString(userlib.RandomBytes(userlib.AESKeySize))

  // Generate Private Key Pair and store in structure
  // If generating function returns an error then return err and quit
  userdata.Private_Key, err = userlib.GenerateRSAKey()
  if err != nil {
    return nil, err
  }

  // Register Public Key with the Keystore
  userlib.KeystoreSet(username, userdata.Private_Key.PublicKey)

  // Create a new map for the files and store it in the structure
  userdata.Files = make(map[string]string)

  // Generate UserKey and store in the structure
  userdata.User_Key = getSha256(userdata.Password + userdata.Username + userdata.Password)


  // The Persistent_user_data structure will be finally stored in the datastore
  var user_to_store Persistent_user_data

  // The encryption key is generated using Argon2 based on password and salt
  // This key is used for encryption and hmac generation
  decoded_salt,_ := hex.DecodeString(userdata.Salt)
  encryption_key := userlib.Argon2Key([]byte(password), decoded_salt, 32)

  // The username and password are stored after hashing
  user_to_store.Username = getSha256(username)
  user_to_store.Password = getSha256(password + userdata.Salt)

  // Salt is stored as plaintext
  user_to_store.Salt = userdata.Salt

  // The Private key structure is marshalled and stored as string
  // in encrypted form using the CFB encryption
  private_key, err := json.Marshal(userdata.Private_Key)
  if err != nil {
    return nil, err
  }
  user_to_store.Private_Key = getCFBEncryptedData(private_key, encryption_key)

  // The file structure is stored in the same way as private key
  files, err := json.Marshal(userdata.Files)
  if err != nil {
    return nil, err
  }
  user_to_store.Files = getCFBEncryptedData(files, encryption_key)

  // The hmac is calculated for all of the above 5 values.
  hmac_data := user_to_store.Username + "\n" + user_to_store.Password + "\n" + user_to_store.Salt +
               "\n" + user_to_store.Private_Key + "\n" + user_to_store.Files
  user_to_store.Hmac = getHmac(hmac_data, encryption_key)

  // The final Persistent_user_data structure is marshalled as json (byte slice)
  // The byte slice is stored in the DataStore using UserKey
  marshalled_user_struct, err := json.Marshal(user_to_store)
  if err != nil {
    return nil, err
  }
  userlib.DatastoreSet(userdata.User_Key, marshalled_user_struct)

  return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {

  var userdata User

  // Get Persistent_user_data corresponding to username and password
  var stored_user Persistent_user_data
  UserKey := getSha256(password + username + password)
  value, ok := userlib.DatastoreGet(UserKey)
  if !ok {
    return nil, errors.New("Datastore error")
  }

  // Since value is valid, unmarshall the json
  // Later check the validity of all values (nothing's been tampered with)

  unmarshal_err := json.Unmarshal(value, &stored_user)
  if(unmarshal_err!=nil){
    return nil,unmarshal_err
  }

  // First check the username and password (with salt)
  if stored_user.Username != getSha256(username) {
    return nil, errors.New("Username is tampered with")
  }

  if stored_user.Password != getSha256(password + stored_user.Salt) {
    return nil,  errors.New("Password/Salt tampered")
  }

  // Now generating the encryption key and checking integrity with HMAC
  decoded_salt,_ := hex.DecodeString(stored_user.Salt)
  encryption_key := userlib.Argon2Key([]byte(password), decoded_salt , 32)
  hmac_data := stored_user.Username + "\n" + stored_user.Password + "\n" + stored_user.Salt +
               "\n" + stored_user.Private_Key + "\n" + stored_user.Files
  expected_hmac := getHmac(hmac_data, encryption_key)

  value1, err1 := hex.DecodeString(expected_hmac)
  value2, err2 := hex.DecodeString(stored_user.Hmac)

  if(err1!=nil || err2 != nil){
    return nil,errors.New("Decode Error") 
  }

  if !userlib.Equal(value1,value2) {
    return nil,  errors.New("Userdata tampered")
  }

  // After the integrity check has been passed, build the userdata
  userdata.Username = username
  userdata.Password = password
  userdata.Salt = stored_user.Salt
  userdata.User_Key = UserKey

  // Get private key by unmarshalling json
  private_key := getCFBDecryptedData(stored_user.Private_Key, encryption_key)
  unmarshal_err  = json.Unmarshal(private_key, &(userdata.Private_Key))
  if(unmarshal_err!=nil){
    return nil,unmarshal_err
  }

  // Get files by unmarshalling json
  files := getCFBDecryptedData(stored_user.Files, encryption_key)
  unmarshal_err = json.Unmarshal(files, &(userdata.Files))
  if(unmarshal_err!=nil){
    return nil,unmarshal_err
  }


  return &userdata, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile (filename string, data []byte) {

  refreshed_user,err := GetUser(userdata.Username,userdata.Password)
  if(err==nil){
    userdata = refreshed_user
  }else {
    return
  }

  filekey := getSha256(filename+userdata.User_Key+"file")

  var filetoken string

  var filestruct File

  file_value, ok := userdata.Files[filekey]

  if(ok ){

    filetoken = file_value

    prev_data, check := userlib.DatastoreGet(filekey)

    if(check){
      var prev_file File
      unmarshal_err := json.Unmarshal(prev_data,&prev_file)
      if(unmarshal_err!=nil){
        return
      }

      if(prev_file.Symlink != "nil"){
        filekey = prev_file.Symlink
      }
    }else{
      return
    }

  } else{
    filetoken = getSha256(userdata.User_Key+filekey+string(userlib.RandomBytes(16)))
    userdata.Files[filekey] = filetoken    //move to persistent storage as well

    change_user_struct_files(userdata)
    
  }

  filestruct.Symlink = "nil"
  filestruct.Number_of_appends = 1

  var s_data = filestruct.Symlink + "\n" + string(filestruct.Number_of_appends)
  decoded_filetoken,err := hex.DecodeString(filetoken)
  if(err!=nil){
    return
  }


  filestruct.Hmac_check = getHmac(s_data, decoded_filetoken)

  marshalled_file_struct, err := json.Marshal(&filestruct)

  if err!=nil {
    return
  }

  userlib.DatastoreSet(filekey,marshalled_file_struct)

  encryption_key := userlib.Argon2Key(decoded_filetoken, []byte("filesecretsalt") , 32)

  encrypted_data := getCFBEncryptedData(data,encryption_key)

  var appendstruct Append
  appendstruct.Data = encrypted_data
  appendstruct.Hmac_check = getHmac(encrypted_data,decoded_filetoken)


  var appendkey = getSha256(filekey+"append"+string(1))
  marshalled_append_struct, err := json.Marshal(&appendstruct)

  if err!=nil {
    return
  }

  userlib.DatastoreSet(appendkey,marshalled_append_struct)

  return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {

  refreshed_user,err := GetUser(userdata.Username,userdata.Password)
  if(err==nil){
    userdata = refreshed_user
  }else{
    return err
  }

  var filekey = getSha256(filename + userdata.User_Key + "file")

  var filetoken []byte

  file_value, ok := userdata.Files[filekey]

  if(ok){
    decoded_filetoken,err:= hex.DecodeString(file_value)

    if(err!=nil){
      return err
    }

    filetoken = decoded_filetoken
  } else{
    return  errors.New("File not created yet")
  }

  value, ok := userlib.DatastoreGet(filekey)
  var file File
  if(ok){
    unmarshal_err := json.Unmarshal(value,&file)
    if(unmarshal_err!=nil){
      return unmarshal_err
    }

    expected_hmac := getHmac(file.Symlink + "\n" + string(file.Number_of_appends), filetoken)

    value1, err1 := hex.DecodeString(expected_hmac)
    value2, err2 := hex.DecodeString(file.Hmac_check)

    if(err1!=nil||err2!=nil){
      return errors.New("Error in decoding")
    }

    if(!userlib.Equal( value1,value2) ){
      return  errors.New("file metadata tampered")
    }

    if(file.Symlink != "nil"){
      filekey = file.Symlink
      value, ok = userlib.DatastoreGet(filekey)
      if(ok){
        unmarshal_err = json.Unmarshal(value,&file)
        if(unmarshal_err!=nil){
          return unmarshal_err
        }

      }else{
        return errors.New("Data not found")
      }

      expected_hmac = getHmac(file.Symlink + "\n" + string(file.Number_of_appends), filetoken)

      value1, err1  = hex.DecodeString(expected_hmac)
      value2, err2  = hex.DecodeString(file.Hmac_check)

      if(err1!=nil||err2!=nil){
        return errors.New("Error in decoding")
      }

      if(!userlib.Equal(value1,value2 )){
        return errors.New("symlink file metadata tampered")
      }

    }


    file.Number_of_appends += 1
    file.Hmac_check = getHmac(file.Symlink + "\n" + string(file.Number_of_appends), filetoken)

    encryption_key := userlib.Argon2Key((filetoken), []byte("filesecretsalt") , 32)

    encrypted_data := getCFBEncryptedData(data,encryption_key)

    var append_struct Append
    append_struct.Data = (encrypted_data)
    append_struct.Hmac_check = getHmac(encrypted_data, filetoken)

    appendkey := getSha256(filekey+"append"+string(file.Number_of_appends))

    marshalled_append_struct, err := json.Marshal(&append_struct)

    if err!=nil {
      return err
    }

    userlib.DatastoreSet(appendkey,marshalled_append_struct)

    marshalled_file_struct, err := json.Marshal(&file)

    if err!=nil {
      return err
    }

    userlib.DatastoreSet(filekey,marshalled_file_struct)

  }else{
    return errors.New("DataStore error")
  }

  return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {


  refreshed_user,err := GetUser(userdata.Username,userdata.Password)
  if(err==nil){
    userdata = refreshed_user
  }else{
    return nil,err
  }

  var filekey = getSha256(filename + userdata.User_Key + "file")
  var filetoken []byte

  file_value , ok := userdata.Files[filekey]

  if(ok){
    decoded_filetoken,err := hex.DecodeString(file_value)
    if(err!=nil){
      return nil,err
    }

    filetoken = decoded_filetoken
  } else{
    return nil,errors.New("file not under your ownership")
  }

  value, ok := userlib.DatastoreGet(filekey)

  var file File
  if(ok){
    unmarshal_err := json.Unmarshal(value,&file)
    if(unmarshal_err!=nil){
      return nil,unmarshal_err
    }

    expected_hmac := getHmac(file.Symlink + "\n" + string(file.Number_of_appends), filetoken)

    value1, err1 := hex.DecodeString(expected_hmac)
    value2, err2 := hex.DecodeString(file.Hmac_check)

    if(err1!=nil || err2!=nil){
      return nil,errors.New("Decode error")
    }

    if(!userlib.Equal( value1,value2 )){
      return nil,errors.New("file metadata tampered")
    }

    if(file.Symlink != "nil"){
      filekey = file.Symlink
      value, ok1 := userlib.DatastoreGet(filekey)
      if(ok1){
        unmarshal_err = json.Unmarshal(value,&file)
        if(unmarshal_err!=nil){
          return nil,unmarshal_err
        }

        expected_hmac = getHmac(file.Symlink + "\n" + string(file.Number_of_appends), filetoken)

        value1, err1 = hex.DecodeString(expected_hmac)
        value2, err2 = hex.DecodeString(file.Hmac_check)

        if(err1!=nil || err2!=nil){
          return nil,errors.New("decode error")
        }

        if(!userlib.Equal(value1,value2)){
          return nil,errors.New("file metadata tampered")
        }
          
      }else{
        return nil,errors.New("File not found")
      }
      
    }

    final_data := []byte{}
    encryption_key := userlib.Argon2Key((filetoken), []byte("filesecretsalt") , 32)

    for i:=1;i<=file.Number_of_appends;i++ {

      appendkey := getSha256(filekey + "append" + string(i))
      append_struct, ok := userlib.DatastoreGet(appendkey)
      if !ok {
        return nil,errors.New("DATA corrupted/deleted")
      }

      var temp Append
      unmarshal_err = json.Unmarshal(append_struct,&temp)
      if(unmarshal_err!=nil){
        return nil,unmarshal_err
      }

      expected_hmac = getHmac(temp.Data, filetoken)

      value1, err1 = hex.DecodeString(expected_hmac)
      value2, err2 = hex.DecodeString(temp.Hmac_check)

      if(err1!=nil || err2!=nil){
        return nil,errors.New("decode error")
      }

      if(!userlib.Equal(value1,value2 )){
        return nil,errors.New("Integrity Break")
      }

      final_data = append(final_data,getCFBDecryptedData(temp.Data,encryption_key)...)
    }

    return final_data,nil
  }
  return nil,errors.New("File Not found")

}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
  msgid string, err error) {

  refreshed_user,err := GetUser(userdata.Username,userdata.Password)
  if(err==nil){
    userdata = refreshed_user
  }else {
    return "",err
  }

  var filekey = getSha256(filename + userdata.User_Key + "file")

  prev_file, check := userlib.DatastoreGet(filekey)
  if(!check){
    return "",errors.New("file corrupted/deleted")
  }

  var prev_struct File
  unmarshal_err := json.Unmarshal(prev_file,&prev_struct)
  if(unmarshal_err!=nil){
    return "",unmarshal_err
  }

  var filetoken []byte

  file_value,ok := userdata.Files[filekey]

  if(ok ){
    decoded_filetoken,err := hex.DecodeString(file_value)
    if(err!=nil){
      return "",err
    }
    filetoken = decoded_filetoken
  } else{
    return "",errors.New("File Not under your ownership")
  }

  expected_hmac := getHmac(prev_struct.Symlink + "\n" + string(prev_struct.Number_of_appends), filetoken)

  value1, err1 := hex.DecodeString(expected_hmac)
  value2, err2 := hex.DecodeString(prev_struct.Hmac_check)

  if(err1!=nil || err2!=nil){
    return "",errors.New("decode error")
  }

  if(!userlib.Equal(value1,value2)){
    return "",errors.New("file metadata tampered")
  }

  if(prev_struct.Symlink != "nil"){
    filekey = prev_struct.Symlink
  }

  encrypted_msg := []byte{}

  value,ok := userlib.KeystoreGet(recipient)
  if(ok){
    encrypted_token,e := userlib.RSAEncrypt(&value,filetoken,[]byte("sharing"))
    if(e!=nil){
      return "",errors.New("Encryption error")
    }
    decoded_filekey,err := hex.DecodeString(filekey)
    if(err!=nil){
      return "",err
    }
    encrypted_msg = append(decoded_filekey,encrypted_token...)
    
    signature, er := userlib.RSASign(userdata.Private_Key,encrypted_msg)
    if(er!=nil){
      return "",errors.New("Signature error")
    }

    final_token := []byte{}
    final_token = append(signature,encrypted_msg...)

    return hex.EncodeToString(final_token),nil

  } else{
    return "",errors.New("could not get recipient's public key")
  }

  return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
  msgid string) error {

  refreshed_user,err := GetUser(userdata.Username,userdata.Password)
  if(err==nil){
    userdata = refreshed_user
  }else{
    return err
  }

  received_msg,err := hex.DecodeString(msgid)
  if(err!=nil){
    return err
  }

  if(len(received_msg)<289){
    return errors.New("Length insufficient!")
  }

  signature := received_msg[0:256]
  msg_filekey := received_msg[256:288]
  msg_token := received_msg[288:]

  sender_publiic_key,ok := userlib.KeystoreGet(sender)

  if(!ok){
    return errors.New("Public key of receiver not found !")
  }

  err = userlib.RSAVerify(&sender_publiic_key,received_msg[256:],signature)
  if(err != nil){
    return errors.New("Signature not verified")
  }

  filetoken, e := userlib.RSADecrypt(userdata.Private_Key,msg_token,[]byte("sharing"))
  if(e!=nil){
    return errors.New("Error in decryption")
  }

  filekey := hex.EncodeToString(msg_filekey)

  receiver_key := getSha256(filename + userdata.User_Key + "file")

  _ , ok = userdata.Files[receiver_key]

  if(ok){
    return errors.New("File Already Exists!")
  }

  userdata.Files[receiver_key] = hex.EncodeToString(filetoken)

  change_user_struct_files(userdata)

  var file File
  file.Symlink = filekey
  file.Number_of_appends = 0
  file.Hmac_check = getHmac(file.Symlink + "\n" + string(file.Number_of_appends), filetoken)

  marshalled_file_struct, err := json.Marshal(file)

  if err!=nil {
    return errors.New("Marshal error")
  }

  userlib.DatastoreSet(receiver_key,marshalled_file_struct)
  return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {


  refreshed_user,err := GetUser(userdata.Username,userdata.Password)
  if(err==nil){
    userdata = refreshed_user
  }else{
    return err
  }

  filekey := getSha256(filename + userdata.User_Key + "file")

  value, ok := userlib.DatastoreGet(filekey)
  if(!ok){
    return errors.New("File corrupted")
  }

  var file File
  unmarshal_err := json.Unmarshal(value,&file)
  if(unmarshal_err!=nil){
    return unmarshal_err
  }

  var filetoken []byte

  file_value, ok := userdata.Files[filekey]
  
  if(ok){
    decoded_filetoken,err := hex.DecodeString(file_value)
    if(err!=nil){
      return err
    }

    filetoken = decoded_filetoken
  } else{
    return errors.New("File not owned")
  }

  encryption_key := userlib.Argon2Key(filetoken, []byte("filesecretsalt") , 32)

  expected_hmac := getHmac(file.Symlink+"\n"+string(file.Number_of_appends),filetoken)

  value1, err1 := hex.DecodeString(expected_hmac)
  value2, err2 := hex.DecodeString(file.Hmac_check)
  if(err1!=nil||err2!=nil){
    return errors.New("decode error!!")
  }

  if(!userlib.Equal(value1,value2 )){
    return errors.New("corrupted")
  }

  if(file.Symlink != "nil"){
    return errors.New("Not allowed Action !")
  }

  new_file_token,_ := hex.DecodeString(getSha256(filename+userdata.User_Key+string(userlib.RandomBytes(16))))

  new_encryption_key := userlib.Argon2Key(new_file_token, []byte("filesecretsalt") , 32)
  userdata.Files[filekey] = hex.EncodeToString(new_file_token)

  change_user_struct_files(userdata)

  file.Hmac_check = getHmac(file.Symlink+"\n"+string(file.Number_of_appends),new_file_token)

  marshalled_file_struct, err := json.Marshal(&file)

  if err!=nil {
    return
  }

  userlib.DatastoreSet(filekey,marshalled_file_struct)

  for i:=1;i<=file.Number_of_appends;i++ {

    appendkey := getSha256(filekey+"append"+string(i))
    append_struct,ok := userlib.DatastoreGet(appendkey)

    if(!ok){
      return errors.New("File corrupted!")
    }
    
    var append_data Append
    unmarshal_err = json.Unmarshal(append_struct,&append_data)
    if(unmarshal_err!=nil){
      return unmarshal_err
    }

    decrypted_data := getCFBDecryptedData(append_data.Data,encryption_key)
    //fmt.Println(string(decrypted_data))
    new_encr_data := getCFBEncryptedData(decrypted_data,new_encryption_key)
    append_data.Data = new_encr_data
    append_data.Hmac_check = getHmac(append_data.Data,new_file_token )

    marshalled_append_struct, err := json.Marshal(&append_data)

    if err!=nil {
      return err
    }

    userlib.DatastoreSet(appendkey,marshalled_append_struct)
  }

  return nil
}