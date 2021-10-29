
create table account (
    id serial primary key,
    username varchar(30),
    password varchar(30),
    email varchar(50),
    age int,
    role varchar(20)
);

