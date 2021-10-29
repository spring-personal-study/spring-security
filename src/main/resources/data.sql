insert into ACCOUNT values (default, 'user', '1111', 'find1086@gmail.com', '23', 'ROLE_USER');
insert into ACCOUNT values (default, 'manager', '1111', 'find1086@gmail.com', '23', 'ROLE_MANAGER');

commit;

select * from ACCOUNT;
