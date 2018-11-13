package main

import (
  "github.com/gin-gonic/gin"
  "net/http"
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

  data := FindData(db)

  c.JSON(200,data)

}
