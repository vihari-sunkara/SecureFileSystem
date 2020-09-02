func main() {
	
	// userlib.DatastoreSet("foo", []byte("bar"))
	// data, valid := userlib.DatastoreGet("foo")
	// if valid {
	// 	fmt.Println("Success!!")
	// }
	// fmt.Println("data: ",string(data))
	// var metadata map[string]map[string]string
	// metadata = make(map[string]map[string]string)
	// var fDetails map[string]string
	// fDetails = make(map[string]string)
	// fDetails["index"]="ind_value"
	// fDetails["secretKey"]="key"
	// metadata["fileName"] = fDetails
	// metaJson,_ := json.Marshal(metadata)
	//print("FileMetaData : ",string(metaJson))

	_,err0:=InitUser("vihari", "19111093")
	if err0!=nil{
		// fmt.Println("error in init user: ",err0)
	}
	_,err0=InitUser("vihari", "sd")
	if err0!=nil{
		// fmt.Println("error in init user**: ",err0)
	}
	_,err0=InitUser("", "pswd")
	if err0!=nil{
		// fmt.Println("Invalid User with empty username: ",err0)
	}
	_,err0=InitUser("user", "")
	if err0!=nil{
		// fmt.Println("Invalid User with empty password: ",err0)
	}
	_,err0=InitUser("", "")
	if err0!=nil{
		// fmt.Println("Invalid User with empty creds: ",err0)
	}
	InitUser("gopi", "19111040")
	InitUser("prakhyat", "191")
	//InitUser("def","pswd")
	var user1 *User
	var err error
	user1, err = GetUser("vihari", "19111093")

	// print("user1: ",user1.Username)

	var user2 *User
	user2, err = GetUser("gopi", "19111040")
// print("user2: ",user2.Username)
	var user3 *User
	user3, err = GetUser("prakhyat", "191")
	if(err!=nil){
		// fmt.Println("error in getting user",err)
	}
//print("user3: ",user3.Username)
// fmt.Println(err)
	// if err!=nil{
	// 	fmt.Println("err in getting user")
	// }
	 setBlockSize(2)
	var data []byte
	b := []byte{'g', 'o', 'l', 'a', 'n', 'g'}
	//appendContent := []byte{'a','b','c'} 
	user1.StoreFile("fname1",b)

	b = []byte{'f', 'u', 'n', 'k', 'y', 'g'}
	//appendContent := []byte{'a','b','c'} 
	user2.StoreFile("fname10",b)
	data,err = user2.LoadFile("fname10",1)

	 // fmt.Println("before overwriting**: ",string(data))

	b = []byte{'d', 'o', 'b', 'a', 'n','g'}
	appendContent := []byte{'v','b','c','d'} 
	appendContent2 := []byte{'g','o','p','i'} 
	user1.StoreFile("fname2",b)
	
	data,err= user1.LoadFile("fname2",0)
	print("data: ",data)
	if(err!=nil){
		// fmt.Println(err)
	}
	// fmt.Println("data: ",string(data))

	err = user1.AppendFile("fname2",appendContent)
	err = user1.AppendFile("fname2",appendContent2)
	if(err!=nil){
		// fmt.Println("err while append: ",err)
	}

	data,err= user1.LoadFile("fname2",6)
	if(err!=nil){
		// fmt.Println("err while loading file ",err)
	}
	// fmt.Println("data: ",string(data))

	msgid,err1:=user2.ShareFile("fname10","vihari")

	if(err1!=nil){
		// fmt.Println("err while sharing: ",err1)
	}
	//fmt.Println("msg while sharing: ",msgid)
	err1 = user1.ReceiveFile("fname20","gopi",msgid)
	if(err1!=nil){
		// fmt.Println("err while receiving: ",err1)
	}
	data,err = user1.LoadFile("fname20",2)
	if(err!=nil){
		// fmt.Println("err while loading file ",err)
	}
	// fmt.Println("data: ",string(data))


	msgid,err1=user1.ShareFile("fname20","prakhyat")

	if(err1!=nil){
		// fmt.Println("err while sharing: ",err1)
	}
	//fmt.Println("msg while sharing: ",msgid)
	err1 = user3.ReceiveFile("fname30","vihari",msgid)
	if(err1!=nil){
		// fmt.Println("err while receiving: ",err1)
	}
	data,err = user3.LoadFile("fname30",2)
	if(err!=nil){
		// fmt.Println("err while loading file ",err)
	}
	b = []byte{'d', 'o', 'f', 'l', 'n', 'k'}
	//appendContent := []byte{'a','b','c'} 
	//user1.StoreFile("fname1",b)
	err = user3.StoreFile("fname30",b)
	if(err!=nil){
		 // fmt.Println("err while overwriting file ",err)
	}
	_,err = user3.LoadFile("fname30",1)
	if err!=nil{
		// fmt.Println("err while overwriting:***")
	}
	// fmt.Println("after overwriting**: ",string(data))
	//fmt.Println("data: ",string(data))
	//fmt.Println("---------------- ")
	err1=user2.RevokeFile("fname10")
	if(err1!=nil){
		// fmt.Println("err while revoking: ",err1)
	}

	err1 = user1.ReceiveFile("fname20","gopi",msgid)
	if(err1!=nil){
		// fmt.Println("zzzzzzzzerr while receiving: ",err1)
	}
	//fmt.Println("---------------- ")
	data,err = user1.LoadFile("fname20",2)
	if(err!=nil){
		// fmt.Println("ZZZZZZZZZZZZZerr while loading file ",err)
	}
// 	fmt.Println("data: ",string(data))
	// var otheruser *User
	//  otheruser,err = GetUser("abc","password")
 //     userJson,_ := json.Marshal(user)
 //     print("user: ",string(userJson))

 //     otherUserJson,_ := json.Marshal(otheruser)
 //     fmt.Println("other user: ",string(otherUserJson))

 //     data,_ := user.LoadFile("fname1",1)
 //     print("len of data fetchced: ",len(data))

 //     err = user.AppendFile("fname1", appendContent)

}
