/*
 * gorm
 */
package main


import (
        "github.com/jinzhu/gorm"
        "encoding/json"
        _ "github.com/jinzhu/gorm/dialects/sqlite"
        _ "fmt"
)

type RequestTable struct {
        gorm.Model
        FirstLine string
        RequestURI string
        Host       string
        SrcIp      string
        SrcPort    string
        DstIp      string
        DstPort    string
        IsResp     int
		StatusCode int
}


type ResponseTable struct{
	gorm.Model
	RequestTable RequestTable `gorm:"foreignkey:RequestRefer"`
	RequestRefer int

    FirstLine    string
	StatusCode   int
    SrcIp        string
    SrcPort      string
    DstIp        string
    DstPort      string
}

type HeaderTable struct{
    gorm.Model
    Type       uint // 1.request header ,2. Response
    Parentid   uint // requestTable or responstTable ID
    Name        string
    Values      string
}

type FormTable struct{
    gorm.Model
    Type       uint // 1.request header ,2. Response
    Parentid   uint // requestTable or responstTable ID
    Name        string
    Values      string
}



type returnReqs struct{
    Reqs   []RequestTable;
    Total  int;
}

func InitDB()(newdb *gorm.DB) {

        newdb, _ = gorm.Open("sqlite3", "./httpdump.db")

		//newdb.LogMode(true)

        newdb.AutoMigrate(&RequestTable{},
            &ResponseTable{},
            &HeaderTable{},
            &FormTable{})

        return newdb
}

func InsertHeaders(db *gorm.DB,n string,v string,t uint,id uint){

    db.Create(&HeaderTable{Type:t,Parentid:id,Name:n,Values:v})
}

func InsertForm(db *gorm.DB,n string,v string,t uint,id uint){

    db.Create(&FormTable{Type:t,Parentid:id,Name:n,Values:v})
}



// insert a request record
func InsertRequestData(db * gorm.DB,req *RequestTable ) (id uint){
    req.IsResp = 1
    db.Create(req)
    return req.ID
}

//update a request record
func UpdateRequestData(db * gorm.DB,req *RequestTable,id uint ){
    db.Model(&RequestTable{}).Where("id=?",id).Updates(req)
}
func UpdateRequestIsResp(db *gorm.DB,req *RequestTable,StatusCode int){

	// IsResp , Column name is_resp
    if req.ID == 0 {
        return
    }
	db.Model(req).Updates(map[string]interface{}{"is_resp":2,"status_code":StatusCode})
}


//insert response record
func InsertResponseData(db *gorm.DB,resp * ResponseTable,req *RequestTable)(id uint){
	// update request status
    // only update IsResp
	UpdateRequestIsResp(db,req,resp.StatusCode)
	//save response
	resp.RequestTable = *req
	db.Create(resp)
    return resp.ID
}

//Update response record
func UpdateResponseData(db *gorm.DB,resp * ResponseTable,req *RequestTable,id uint){
	// update request status again,
    // update StatusCode

	UpdateRequestIsResp(db,req,resp.StatusCode)

	//update response
    db.Model(&ResponseTable{}).Where("id=?",id).Updates(resp)
}

// query all request access record
func FindRequestData(db *gorm.DB) (reqs  []RequestTable){

    db.Order("ID desc").Find(&reqs)

    return reqs
}

// query page data
func FindRequestDataPage(db * gorm.DB,page int, pagesize int) (ret returnReqs){

    var reqs []RequestTable;
    var count int;

	db.Order("ID desc").Limit(pagesize).Offset(page * pagesize).Find(&reqs)

    db.Table("request_tables").Count(&count)

    ret.Reqs  = reqs
    ret.Total = count
	return ret

}

// Get a request id
func FindRequestFirst(db * gorm.DB,SrcIp string,SrcPort string,DstIp string,DstPort string) (req RequestTable){

	db.Where(RequestTable{IsResp:1, SrcIp: DstIp, SrcPort:DstPort,DstIp:SrcIp,DstPort:SrcPort}).First(&req)

	return req
}

// Get request and response information
func FindRequestById(db * gorm.DB,id int)(map[string]interface{}){

    var req RequestTable;
    var resp ResponseTable;
    var reqH,respH []HeaderTable;
    var reqForm []FormTable;

    returnJson := make(map[string]interface{})
    respJson := make(map[string]interface{})
    reqHJson := make([]map[string]interface{},50)
    reqFJson := make([]map[string]interface{},100)
    respHJson := make([]map[string]interface{},50)

    db.First(&req,id)

    // converting to map
    inrec, _ := json.Marshal(&req)
    json.Unmarshal(inrec, &returnJson)

    db.Model(&req).Related(&resp, "RequestRefer")

    // converting to map
    inresp, _ := json.Marshal(&resp)
    json.Unmarshal(inresp, &respJson)

    returnJson["resp"] = respJson

    // get request Header
    db.Where("parentid=? and type=1",req.ID).Find(&reqH)
    // converting to map
    inreqh, _ := json.Marshal(&reqH)
    json.Unmarshal(inreqh, &reqHJson)
    returnJson["reqh"] = reqHJson

    // get request Form 
    db.Where("parentid=? and type=1",req.ID).Find(&reqForm)
    // converting to map
    inreqform, _ := json.Marshal(&reqForm)
    json.Unmarshal(inreqform, &reqFJson)
    returnJson["reqform"] = reqFJson


    // get response Header
    db.Where("parentid=? and type=2",resp.ID).Find(&respH)
    // converting to map
    inresph, _ := json.Marshal(&respH)
    json.Unmarshal(inresph, &respHJson)
    returnJson["resph"] = respHJson


    return returnJson
}
