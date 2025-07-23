DROP ROLE username;
CREATE ROLE username WITH LOGIN PASSWORD 'password';
ALTER ROLE username CREATEDB;
GRANT ALL PRIVILEGES ON DATABASE book_social_network TO username;