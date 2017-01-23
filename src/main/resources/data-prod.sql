INSERT INTO user (username, password_hash) VALUES ('admin', '$2a$10$QZDQ5SYfwvYFnHBEIYyjo.R8v.XAP7JItFKZcq9OI/t6xb8VbgfFW'); -- password123
INSERT INTO user (username, password_hash) VALUES ('user', '$2a$10$QZDQ5SYfwvYFnHBEIYyjo.R8v.XAP7JItFKZcq9OI/t6xb8VbgfFW'); -- password123

INSERT INTO role (name) VALUES ('ROLE_ADMIN');
INSERT INTO role (name) VALUES ('ROLE_USER');

INSERT INTO user_role (user_id, role_id) VALUES ('1', '1');
INSERT INTO user_role (user_id, role_id) VALUES ('1', '2');
INSERT INTO user_role (user_id, role_id) VALUES ('2', '2');
