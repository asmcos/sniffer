/*
 * the config for main
 * Author:asmcos
 * Date:2021.2
 */


package main

import (

    "encoding/json"
    "io/ioutil"
    "log"
)

/*****************************
 config value
******************************/
var colorReset = "\033[0m"

var colorRed = "\033[31m"




func loadConfig(){

    f, err := ioutil.ReadFile("sniffer.json")
    if err != nil {
        log.Println("**********************************************")
        log.Println(colorRed,"Warning: Read config sniffer.json fail,use default config value.", err,colorReset)
        log.Println("**********************************************")
        return
    }

    var configData map[string]interface{}
    err = json.Unmarshal([]byte(f), &configData)
    if err != nil {
        log.Println("sniffer.json err,user default config",err)
        return
    }

    log.Println(configData)

    *iface    = configData["device"].(string)
    *port     = int(configData["port"].(float64))

    *djslen   = int(configData["jslength"].(float64))
    *dhtmllen = int(configData["htmllength"].(float64))

    *danystr  = configData["dumpanystr"].(string)
    *danylen  = int(configData["dumpanylen"].(float64))

}
