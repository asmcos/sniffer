package main

import (
  "github.com/gin-gonic/gin"
  "net/http"
  "strconv"
)

func InitHdServer (){

  router := gin.Default()

  router.StaticFS("/html", http.Dir("html"))


  api := router.Group("/api")
  api.GET("/",rootPath)

  // default port :8080
  router.Run()
}


func rootPath(c *gin.Context){

  var defaultpage = 1;
  var defaultpagesize = 10;

  if page, isExist := c.GetQuery("page"); isExist == true {
        defaultpage, _ = strconv.Atoi(page)
        if defaultpage > 0{
            defaultpage -= 1
        }
  }

  if pagesize, isExist := c.GetQuery("pagesize"); isExist == true {
        defaultpagesize, _ = strconv.Atoi(pagesize)
  }

  data := FindRequestDataPage(db,defaultpage,defaultpagesize)

  c.JSON(200,data)

}
