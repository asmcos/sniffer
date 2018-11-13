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
}

func init_db()(newdb *gorm.DB) {

        newdb, _ = gorm.Open("sqlite3", "./httpdump.db")

        newdb.AutoMigrate(&RequestTable{})

        return newdb
}

func InsertData(db * gorm.DB,req *RequestTable ){
  db.Create(req)
}

func FindData(db *gorm.DB) (reqs  []RequestTable){


  db.Order("ID desc").Find(&reqs)

  return reqs
}

/*
        p1 := Person{FirstName: "John", LastName: "Doe"}
        p2 := Person{FirstName: "Jane", LastName: "Smith"}

        db.Create(&p1)
        var ps []Person

        fmt.Println("-------1------")
        db.Find(&ps)
        for _,k := range ps{
                fmt.Println(k)
        }


        db.Create(&p2)
        fmt.Println("-------2------")
        db.Find(&ps)
        for _,k := range ps{
                fmt.Println(k)
        }
*/
