package database

import (
	"database/sql"
	"github.com/helderfarias/oauthprovider-go/model"
	"log"
)

type PostgresClientStorage struct {
	DB *sql.DB
}

func (c *PostgresClientStorage) Save(entity *model.Client) error {
	stmt, err := c.DB.Prepare("INSERT INTO sso.oauth_clients(name, secret, status, last_lock_at, last_unlock_at) VALUES ($1, $2, $3, $4, $5)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	res, err := stmt.Exec(entity.Name, entity.Secret, entity.Status, nil, nil)
	if err != nil {
		return err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return err
	}

	entity.ID = id
	return nil
}

func (c *PostgresClientStorage) FindById(id string) *model.Client {
	rows, err := c.DB.Query("SELECT id, name, status FROM sso.oauth_clients WHERE name = $1", id)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer rows.Close()

	if rows.Next() {
		cli := &model.Client{}

		err = rows.Scan(&cli.ID, &cli.Name, &cli.Status)
		if err != nil {
			log.Println(err)
			return nil
		}

		return cli
	}

	return nil
}

func (c *PostgresClientStorage) Delete(entity *model.Client) error {
	stmt, err := c.DB.Prepare("DELETE FROM sso.oauth_clients WHERE id = $1")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(entity.ID)
	if err != nil {
		return err
	}

	return nil
}

func (c *PostgresClientStorage) FindByCredencials(clientId, clientSecret string) *model.Client {
	rows, err := c.DB.Query("SELECT id, name, status FROM sso.oauth_clients WHERE secret = $1 and name  = $2", clientSecret, clientId)
	if err != nil {
		log.Println(err)
		return nil
	}
	defer rows.Close()

	if rows.Next() {
		cli := &model.Client{}

		err = rows.Scan(&cli.ID, &cli.Name, &cli.Status)
		if err != nil {
			log.Println(err)
			return nil
		}

		return cli
	}

	return nil
}
