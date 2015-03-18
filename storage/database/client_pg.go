package database

import (
	"database/sql"
	"github.com/helderfarias/oauthprovider-go/logger"
	"github.com/helderfarias/oauthprovider-go/model"
)

type PostgresClientStorage struct {
	DB *sql.DB
}

func (c *PostgresClientStorage) Save(entity *model.Client) error {
	var sequence int64
	err := c.DB.QueryRow("SELECT nextval('sso.oauth_client_seq')").Scan(&sequence)
	if err != nil {
		logger.Error("PostgresAccessTokenStorage --> Save(): %s", err)
		return err
	}

	stmt, err := c.DB.Prepare("INSERT INTO sso.oauth_clients(name, secret, status, id) VALUES ($1, $2, $3, $4)")
	if err != nil {
		logger.Error("PostgresClientStorage --> Save(): %s", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(entity.Name, entity.Secret, entity.Status, sequence)
	if err != nil {
		logger.Error("PostgresClientStorage --> Save(): %s", err)
		return err
	}

	entity.ID = sequence
	return nil
}

func (c *PostgresClientStorage) FindById(id string) *model.Client {
	rows, err := c.DB.Query("SELECT id, name, status FROM sso.oauth_clients WHERE name = $1", id)
	if err != nil {
		logger.Error("PostgresClientStorage --> FindById(): %s", err)
		return nil
	}
	defer rows.Close()

	if rows.Next() {
		cli := &model.Client{}

		err = rows.Scan(&cli.ID, &cli.Name, &cli.Status)
		if err != nil {
			logger.Error("PostgresClientStorage --> FindById(): %s", err)
			return nil
		}

		return cli
	}

	return nil
}

func (c *PostgresClientStorage) Delete(entity *model.Client) error {
	stmt, err := c.DB.Prepare("DELETE FROM sso.oauth_clients WHERE id = $1")
	if err != nil {
		logger.Error("PostgresClientStorage --> Delete(): %s", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(entity.ID)
	if err != nil {
		logger.Error("PostgresClientStorage --> Delete(): %s", err)
		return err
	}

	return nil
}

func (c *PostgresClientStorage) FindByCredencials(clientId, clientSecret string) *model.Client {
	rows, err := c.DB.Query("SELECT id, name, status FROM sso.oauth_clients WHERE secret = $1 and name  = $2", clientSecret, clientId)
	if err != nil {
		logger.Error("PostgresClientStorage --> FindByCredencials(): %s", err)
		return nil
	}
	defer rows.Close()

	if rows.Next() {
		cli := &model.Client{}

		err = rows.Scan(&cli.ID, &cli.Name, &cli.Status)
		if err != nil {
			logger.Error("PostgresClientStorage --> FindByCredencials(): %s", err)
			return nil
		}

		return cli
	}

	return nil
}
