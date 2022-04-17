-- DATABASE
CREATE DATABASE sclog
  DEFAULT CHARACTER SET utf8
  DEFAULT COLLATE utf8_general_ci;
  
CREATE USER 'sclog'@'%' IDENTIFIED BY 'sclog';
GRANT SELECT,INSERT,update ON sclog.* TO 'sclog'@'%';
GRANT EXECUTE ON sclog.* TO 'sclog'@'%';

flush privileges;
