package database

import (
	"database/sql"
	"github.com/helderfarias/oauthprovider-go/logger"
	"github.com/helderfarias/oauthprovider-go/model"
	"time"
)

type PostgresAccessTokenStorage struct {
	DB *sql.DB
}

func (c *PostgresAccessTokenStorage) Save(entity *model.AccessToken) error {
	var sequence int64
	err := c.DB.QueryRow("SELECT nextval('sso.oauth_acces_token_seq')").Scan(&sequence)
	if err != nil {
		logger.Error("PostgresAccessTokenStorage --> Save(): %s", err)
		return err
	}

	stmt, err := c.DB.Prepare("INSERT INTO sso.oauth_access_tokens(token, expires_at, created_at, user_id, client_id, id) VALUES ($1, $2, $3, $4, $5, $6)")
	if err != nil {
		logger.Error("PostgresAccessTokenStorage --> Save(): %s", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(entity.Token, entity.ExpiresAt, time.Now(), entity.User.ID, entity.Client.ID, sequence)
	if err != nil {
		logger.Error("PostgresAccessTokenStorage --> Save(): %s", err)
		return err
	}

	entity.ID = sequence
	return nil
}

func (c *PostgresAccessTokenStorage) FindById(id string) *model.AccessToken {
	rows, err := c.DB.Query("SELECT id, token, expires_at, created_at, user_id, client_id FROM sso.oauth_access_tokens WHERE token = $1", id)
	if err != nil {
		logger.Error("PostgresAccessTokenStorage --> FindById(): %s", err)
		return nil
	}
	defer rows.Close()

	if rows.Next() {
		token := &model.AccessToken{}
		token.User = &model.User{}
		token.Client = &model.Client{}

		err = rows.Scan(&token.ID, &token.Token, &token.ExpiresAt, &token.CreatedAt, &token.User.ID, &token.Client.ID)
		if err != nil {
			logger.Error("PostgresAccessTokenStorage --> FindById(): %s", err)
			return nil
		}

		return token
	}

	return nil
}

func (c *PostgresAccessTokenStorage) Delete(entity *model.AccessToken) error {
	stmt, err := c.DB.Prepare("DELETE FROM sso.oauth_access_tokens WHERE id = $1")
	if err != nil {
		logger.Error("PostgresAccessTokenStorage --> Delete(): %s", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(entity.ID)
	if err != nil {
		logger.Error("PostgresAccessTokenStorage --> Delete(): %s", err)
		return err
	}

	return nil
}
