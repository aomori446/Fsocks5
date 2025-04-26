package main

func HasUser(username string, password string) bool {
	// TODO check database
	if username == "admin" && password == "password" {
		return true
	}
	return false
}
