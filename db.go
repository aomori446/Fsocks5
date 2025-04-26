package main

func HasUser(username string, password string) bool {
	// Hardcoded authentication logic (can be replaced with a DB check)
	if username == "admin" && password == "password" {
		return true
	}
	return false
}
