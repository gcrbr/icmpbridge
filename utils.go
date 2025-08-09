package main

import (
	"fmt"
	"net"
	"time"
	"reflect"
)

const AUTHORIZED = "\x00"
const UNAUTHORIZED = "\x01"

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0]) << 24 | uint32(ip[1]) << 16 | uint32(ip[2]) << 8 | uint32(ip[3])
}

func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip >> 24) & 0xff,
		(ip >> 16) & 0xff,
		(ip >> 8) & 0xff,
		ip & 0xff)
}

func removeElement(slice interface{}, value interface{}) interface{} {
	sliceValue := reflect.ValueOf(slice)
	if sliceValue.Kind() != reflect.Slice {
		return slice
	}

	newSlice := reflect.MakeSlice(sliceValue.Type(), 0, sliceValue.Len())
	for i := 0; i < sliceValue.Len(); i++ {
		if !reflect.DeepEqual(sliceValue.Index(i).Interface(), value) {
			newSlice = reflect.Append(newSlice, sliceValue.Index(i))
		}
	}
	return newSlice.Interface()
}

const CLIENT_TIMEOUT = 5 * 60
func cleanClientList() {
	for {
		currentTime := time.Now().Unix()
		clientsMutex.Lock()
		for addr, client := range clients {
			if (currentTime - client.lastReqTime) >= CLIENT_TIMEOUT {
				delete(clients, addr)
			}
		}
		clientsMutex.Unlock()
		time.Sleep(30 * time.Second)
	}
}