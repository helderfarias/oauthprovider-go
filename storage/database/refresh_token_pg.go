package database

import (
	"database/sql"
	. "github.com/helderfarias/oauthprovider-go/log"
	"github.com/helderfarias/oauthprovider-go/model"
	"time"
)

type PostgresRefreshTokenStorage struct {
	DB *sql.DB
}

func (c *PostgresRefreshTokenStorage) Save(entity *model.RefreshToken) error {
	var sequence int64
	err := c.DB.QueryRow("SELECT nextval('sso.oauth_refresh_token_seq')").Scan(&sequence)
	if err != nil {
		Logger.Error("PostgresAccessTokenStorage --> Save(): %s", err)
		return err
	}

	stmt, err := c.DB.Prepare("INSERT INTO sso.oauth_refresh_tokens(token, expires_at, created_at, user_id, client_id, access_token_id, id) VALUES ($1, $2, $3, $4, $5, $6, $7)")
	if err != nil {
		Logger.Error("PostgresRefreshTokenStorage --> Save(): %s", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(entity.Token, entity.ExpiresAt, time.Now(), entity.User.ID, entity.Client.ID, entity.AccessToken.ID, sequence)
	if err != nil {
		Logger.Error("PostgresAccessTokenStorage --> Save(): %s", err)
		return err
	}

	entity.ID = sequence
	return nil
}

func (c *PostgresRefreshTokenStorage) FindById(id string) *model.RefreshToken {
	rows, err := c.DB.Query("SELECT id, token, expires_at, created_at, user_id, client_id, access_token_id FROM sso.oauth_refresh_tokens WHERE token = $1", id)
	if err != nil {
		Logger.Error("PostgresRefreshTokenStorage --> FindById(): %s", err)
		return nil
	}
	defer rows.Close()

	var refreshToken *model.RefreshToken
	if rows.Next() {
		refreshToken = &model.RefreshToken{}
		refreshToken.User = &model.User{}
		refreshToken.Client = &model.Client{}
		refreshToken.AccessToken = &model.AccessToken{}

		err = rows.Scan(&refreshToken.ID, &refreshToken.Token, &refreshToken.ExpiresAt, &refreshToken.CreatedAt, &refreshToken.User.ID, &refreshToken.Client.ID, &refreshToken.AccessToken.ID)
		if err != nil {
			Logger.Error("PostgresRefreshTokenStorage --> FindById(): %s", err)
			return nil
		}
	}

	if refreshToken != nil {
		refreshToken.AccessToken = c.findAccessTokenById(refreshToken.AccessToken.ID)
	}

	return refreshToken
}

func (c *PostgresRefreshTokenStorage) Delete(entity *model.RefreshToken) error {
	stmt, err := c.DB.Prepare("DELETE FROM sso.oauth_refresh_tokens WHERE id = $1")
	if err != nil {
		Logger.Error("PostgresRefreshTokenStorage --> Delete(): %s", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(entity.ID)
	if err != nil {
		Logger.Error("PostgresRefreshTokenStorage --> Delete(): %s", err)
		return err
	}

	return nil
}

func (c *PostgresRefreshTokenStorage) DeleteByAccessToken(accessToken *model.AccessToken) error {
	stmt, err := c.DB.Prepare("DELETE FROM sso.oauth_refresh_tokens WHERE access_token_id = $1")
	if err != nil {
		Logger.Error("PostgresRefreshTokenStorage --> DeleteByAccessToken(): %s", err)
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(accessToken.ID)
	if err != nil {
		Logger.Error("PostgresRefreshTokenStorage --> DeleteByAccessToken(): %s", err)
		return err
	}

	return nil
}

func (p *PostgresRefreshTokenStorage) findAccessTokenById(id int64) *model.AccessToken {
	rows, err := p.DB.Query("SELECT id, token, expires_at, created_at, user_id, client_id FROM sso.oauth_access_tokens WHERE id = $1", id)
	if err != nil {
		Logger.Error("PostgresAccessTokenStorage --> FindById(): %s", err)
		return nil
	}
	defer rows.Close()

	if rows.Next() {
		token := &model.AccessToken{}
		token.User = &model.User{}
		token.Client = &model.Client{}

		err = rows.Scan(&token.ID, &token.Token, &token.ExpiresAt, &token.CreatedAt, &token.User.ID, &token.Client.ID)
		if err != nil {
			Logger.Error("PostgresAccessTokenStorage --> FindById(): %s", err)
			return nil
		}

		return token
	}

	return nil
}
