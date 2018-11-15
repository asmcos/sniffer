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
        isResp     int
}

func init_db()(newdb *gorm.DB) {

        newdb, _ = gorm.Open("sqlite3", "./httpdump.db")

        newdb.AutoMigrate(&RequestTable{})

        return newdb
}

// insert a request record
func InsertData(db * gorm.DB,req *RequestTable ){
    req.isResp = 0
    db.Create(req)
}

// query all access record
func FindData(db *gorm.DB) (reqs  []RequestTable){


    db.Order("ID desc").Find(&reqs)

    return reqs
}
