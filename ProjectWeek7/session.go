package main

import (
	"net/http"
	"github.com/satori/go.uuid"
)

func getUser(w http.ResponseWriter, req *http.Request) user {

	c, err := req.Cookie("session")
	if err != nil {
		sID := uuid.NewV4()
		c = &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
	}
	http.SetCookie(w, c)

	var u user

	if s, ok := dbSessions[c.Value];ok {

		dbSessions[c.Value] = s
		u = dbUsers[s.un]
	}
	return u
}

func alreadyLoggedIn(w http.ResponseWriter, req *http.Request) bool {
	c, err := req.Cookie("session")
	if err != nil {
		return false
	}
	s, ok := dbSessions[c.Value]
	if ok {

		dbSessions[c.Value] = s
	}
	_, ok = dbUsers[s.un]

	http.SetCookie(w, c)
	return ok
}
