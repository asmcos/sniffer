/*
 * gorm
 */
package main


import (
        "github.com/jinzhu/gorm"
        _ "github.com/jinzhu/gorm/dialects/sqlite"
        _ "fmt"
)

type RequestTable struct {
        gorm.Model
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

	StatusCode   int
    SrcIp        string
    SrcPort      string
    DstIp        string
    DstPort      string
}


func init_db()(newdb *gorm.DB) {

        newdb, _ = gorm.Open("sqlite3", "./httpdump.db")

		// newdb.LogMode(true)

        newdb.AutoMigrate(&RequestTable{})
        newdb.AutoMigrate(&ResponseTable{})

        return newdb
}

// insert a request record
func InsertRequestData(db * gorm.DB,req *RequestTable ){
    req.IsResp = 1
    db.Create(req)
}

func UpdateRequestIsResp(db *gorm.DB,req *RequestTable,StatusCode int){

	// IsResp , Column name is_resp

	db.Model(req).Updates(map[string]interface{}{"is_resp":2,"status_code":StatusCode})
}

//insert response record
func InsertResponseData(db *gorm.DB,resp * ResponseTable,req *RequestTable){
	// update request status
	UpdateRequestIsResp(db,req,resp.StatusCode)

	//save response
	resp.RequestTable = *req
	db.Create(resp)
}

// query all request access record
func FindRequestData(db *gorm.DB) (reqs  []RequestTable){

    db.Order("ID desc").Find(&reqs)

    return reqs
}

// query page data
func FindRequestDataPage(db * gorm.DB,page int, pagesize int) (reqs []RequestTable){

	db.Order("ID desc").Limit(pagesize).Offset(page * pagesize).Find(&reqs)
	return reqs

}


func FindRequest(db * gorm.DB,SrcIp string,SrcPort string,DstIp string,DstPort string) (req RequestTable){

	db.Where(RequestTable{IsResp:1, SrcIp: DstIp, SrcPort:DstPort,DstIp:SrcIp,DstPort:SrcPort}).First(&req)

	return req
}


