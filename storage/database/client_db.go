package database

import (
	"database/sql"
	"fmt"
	"github.com/helderfarias/oauthprovider-go/model"
)

type DatabaseClientStorage struct {
	Connection *sql.DB
}

func (c *DatabaseClientStorage) Save(entity *model.Client) {
}

func (c *DatabaseClientStorage) FindById(id string) *model.Client {
	rows, err := db.Query("SELECT * FROM sso.oauth_clients")
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		var uid int
		var username string
		var department string
		var created time.Time

		err = rows.Scan(&uid, &username, &department, &created)
		if err != nil {
			panic(err)
		}

		fmt.Println("uid | username | department | created ")
		fmt.Printf("%3v | %8v | %6v | %6v\n", uid, username, department, created)
	}

	return nil
}

func (c *DatabaseClientStorage) Delete(entity *model.Client) {

}

func (c *DatabaseClientStorage) FindByCredencials(clientId, clientSecret string) *model.Client {
	return nil
}
