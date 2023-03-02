DROP DATABASE IF EXISTS dev;
CREATE DATABASE dev;
USE dev;

CREATE TABLE users (
  `id` INT(10) PRIMARY KEY NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(32) NOT NULL,
  `password` VARCHAR(256) NOT NULL,
  `firstname` VARCHAR(32) NOT NULL,
  `lastname` VARCHAR(32) NOT NULL,
  `email` VARCHAR(64) NULL,
  UNIQUE INDEX `email_UNIQUE` (`email` ASC),
  UNIQUE INDEX `uid_UNIQUE` (`id` ASC)
);

CREATE TABLE projects (
  `pid` INT(10) PRIMARY KEY NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(64) NOT NULL,
  `color` ENUM(
	'red', 'blaze', 'orange', 'dandelion', 'yellow', 'chartreuse',
    'green', 'emerald', 'teal', 'turquiose', 'skyblue', 'blue',
    'deepblue', 'indigo', 'purple ', 'fuschia', 'magenta', 'rose') DEFAULT 'rose' NOT NULL,
  `description` MEDIUMTEXT NOT NULL,
  UNIQUE INDEX `pid_UNIQUE` (`pid` ASC)
);

CREATE TABLE roles (
  `rid` INT(10) PRIMARY KEY NOT NULL AUTO_INCREMENT,
  `rank` ENUM('Member', 'Leader', 'Owner') NOT NULL,
  `id` INT(10),
  `pid` INT(10),
  FOREIGN KEY (`id`) REFERENCES users(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`pid`) REFERENCES projects(`pid`) ON DELETE CASCADE
);

CREATE TABLE tasks (
  `tid` INT(10) PRIMARY KEY NOT NULL AUTO_INCREMENT,
  `pid` INT(10) NOT NULL,
  `name` VARCHAR(64) NOT NULL,
  `description` MEDIUMTEXT NOT NULL,
  `status` ENUM('NOT_STARTED', 'IN_PROGRESS', 'OVERDUE', 'COMPLETED', 'COMPLETED_LATE', 'SKIPPED') NOT NULL,
  `deadline` DATE NOT NULL,
  `completed` DATE NULL,
  FOREIGN KEY (`pid`) REFERENCES projects(`pid`) ON DELETE CASCADE
);

CREATE TABLE subtasks (
  `stid` INT(10) PRIMARY KEY NOT NULL AUTO_INCREMENT,
  `tid` INT(10) NOT NULL,
  `name` VARCHAR(64) NOT NULL,
  `status` ENUM('NOT_STARTED', 'IN_PROGRESS', 'OVERDUE', 'COMPLETED', 'COMPLETED_LATE', 'SKIPPED') NOT NULL,
  `description` MEDIUMTEXT NOT NULL,
  `deadline` DATE NULL,
  `completed` DATE NULL,
  FOREIGN KEY (`tid`) REFERENCES tasks(`tid`) ON DELETE CASCADE
);
CREATE TABLE assignments (
  `aid` INT(10) PRIMARY KEY NOT NULL AUTO_INCREMENT,
  `id` INT(10) NOT NULL,
  `tid` INT(10) NOT NULL,
  `request` ENUM('START', 'SUBMIT', 'SKIP') NULL,
  FOREIGN KEY (`id`) REFERENCES users(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`tid`) REFERENCES tasks(`tid`) ON DELETE CASCADE
);

CREATE TABLE changes (
  `cid` INT(10) PRIMARY KEY NOT NULL AUTO_INCREMENT,
  `tid` INT(10) NOT NULL,
  `action` TEXT NULL,
  `time` DATETIME NOT NULL,
  FOREIGN KEY (`tid`) REFERENCES tasks(`tid`) ON DELETE CASCADE
);

CREATE TABLE forms (
  `fid` INT(10) PRIMARY KEY NOT NULL AUTO_INCREMENT,
  `id` INT(10) NOT NULL,
  `tid` INT(10) NOT NULL,
  FOREIGN KEY (`tid`) REFERENCES tasks(`tid`) ON DELETE CASCADE,
  FOREIGN KEY (`id`) REFERENCES users(`id`) ON DELETE CASCADE
);

CREATE TABLE evaluations (
  `eid` INT(10) PRIMARY KEY NOT NULL AUTO_INCREMENT,
  `fid` INT(10) NOT NULL,
  `id` INT(10) NOT NULL,
  `status` ENUM('NOT_SUBMITTED', 'SUBMITTED') DEFAULT 'NOT_SUBMITTED' NOT NULL,
  `comment` MEDIUMTEXT NULL,
  `disabled` BOOLEAN DEFAULT false,
  FOREIGN KEY (`fid`) REFERENCES forms(`fid`) ON DELETE CASCADE,
  FOREIGN KEY (`id`) REFERENCES users(`id`) ON DELETE CASCADE
);

CREATE TABLE questions (
  `qid` INT(10) PRIMARY KEY NOT NULL AUTO_INCREMENT,
  `eid` INT(10) NOT NULL,
  `category` ENUM('Communication', 'Feedback', 'Attendance', 'Responsibility', 'Performance', 'Efficiency') NOT NULL,
  `answer` INT(1),
  FOREIGN KEY (`eid`) REFERENCES evaluations(`eid`) ON DELETE CASCADE
);

CREATE TABLE messages (
  `mid` INT(10) PRIMARY KEY NOT NULL AUTO_INCREMENT,
  `id` INT(10) NOT NULL,
  `id2` INT(10) NOT NULL,
  `subject` VARCHAR(64) NOT NULL,
  `content` MEDIUMTEXT NOT NULL,
  `status` ENUM('READ', 'UNREAD') NOT NULL DEFAULT 'UNREAD',
  `date` DATE NULL,
  FOREIGN KEY (`id`) REFERENCES users(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`id2`) REFERENCES users(`id`) ON DELETE CASCADE
);

DROP PROCEDURE IF EXISTS add_evaluations;
DELIMITER $$
CREATE PROCEDURE add_evaluations (form_id INT, user_id INT, task_id INT)
BEGIN
	DECLARE done BOOLEAN DEFAULT false;
	DECLARE target INT;
    DECLARE target_cursor CURSOR FOR
		SELECT assignments.id FROM assignments
        WHERE (assignments.tid = task_id AND NOT assignments.id = user_id)
        ORDER BY RAND();
	DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = true;
    OPEN target_cursor;

    add_data: LOOP
		FETCH target_cursor INTO target;
		IF done THEN LEAVE add_data;
        END IF;

        INSERT INTO evaluations (`fid`, `id`, `status`, `comment`, `disabled`)
        VALUES (form_id, target, 'SUBMITTED', null, CASE FLOOR(RAND() * 2) WHEN 0 THEN false ELSE true END);

        SET @new_evaluation_id = (SELECT evaluations.eid FROM evaluations WHERE (evaluations.fid = form_id AND evaluations.id = target));
		INSERT INTO questions (`eid`, `category`, `answer`)
		VALUES (@new_evaluation_id, 'Communication', FLOOR((RAND() * 5) + 1)),
			   (@new_evaluation_id, 'Feedback', FLOOR((RAND() * 5) + 1)),
               (@new_evaluation_id, 'Attendance', FLOOR((RAND() * 5) + 1)),
               (@new_evaluation_id, 'Responsibility', FLOOR((RAND() * 5) + 1)),
               (@new_evaluation_id, 'Performance', FLOOR((RAND() * 5) + 1)),
               (@new_evaluation_id, 'Efficiency', FLOOR((RAND() * 5) + 1));
    END LOOP add_data;
    CLOSE target_cursor;
END $$;
DELIMITER ;

DROP PROCEDURE IF EXISTS add_forms;
DELIMITER $$
CREATE PROCEDURE add_forms (task_id INT)
BEGIN
	DECLARE done BOOLEAN DEFAULT false;
	DECLARE member_id INT;
    DECLARE member_cursor CURSOR FOR
		SELECT assignments.id FROM assignments
        WHERE assignments.tid = task_id
        ORDER BY RAND();
	DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = true;
    OPEN member_cursor;

    add_forms: LOOP
		FETCH member_cursor INTO member_id;
		IF done THEN LEAVE add_forms;
        END IF;

        INSERT INTO forms (`id`, `tid`) VALUES (member_id, task_id);
        SET @new_form_id = (SELECT forms.fid FROM forms WHERE (forms.id = member_id AND forms.tid = task_id));
        CALL add_evaluations(@new_form_id, member_id, task_id);
    END LOOP add_forms;
    CLOSE member_cursor;
END $$;
DELIMITER ;

DROP PROCEDURE IF EXISTS add_history;
DELIMITER $$
CREATE PROCEDURE add_history (task_id INT, task_request ENUM('SKIP', 'SUBMIT'), completed_date DATE)
BEGIN
	DECLARE done BOOLEAN DEFAULT false;
	DECLARE assignment_id INT;
    DECLARE assignment CURSOR FOR
		SELECT assignments.aid FROM assignments
        WHERE assignments.tid = task_id
        ORDER BY RAND();
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = true;
    SET @change_count = 0;
    OPEN assignment;
    add_start: LOOP
		FETCH assignment INTO assignment_id;
		IF done THEN LEAVE add_start;
        END IF;

		SET @firstname = (SELECT users.firstname FROM users INNER JOIN assignments ON assignments.id = users.id WHERE assignments.aid = assignment_id AND assignments.tid = task_id LIMIT 1);
		SET @lastname = (SELECT users.lastname FROM users INNER JOIN assignments ON assignments.id = users.id WHERE assignments.aid = assignment_id AND assignments.tid = task_id LIMIT 1);
        SET @assignment_action = (CASE @change_count WHEN 0 THEN 'REQUEST' ELSE 'CONFIRM' END);

        INSERT INTO changes (`tid`, `action`, `time`)
        VALUES (task_id, CONCAT(CONCAT(@firstname, ' ', @lastname), (CASE @assignment_action WHEN 'REQUEST' THEN ' requested to ' ELSE ' confirmed the request to ' END), 'start this task'), DATE_SUB(completed_date, INTERVAL (4 - @change_count - 1) DAY));

        SET @change_count = @change_count + 1;
    END LOOP add_start;
	CLOSE assignment;

    SET done = false;
    SET @change_count = 0;
	OPEN assignment;
    add_complete: LOOP
		FETCH assignment INTO assignment_id;
		IF done THEN LEAVE add_complete;
        END IF;
		SET @firstname = (SELECT users.firstname FROM users INNER JOIN assignments ON assignments.id = users.id WHERE assignments.aid = assignment_id AND assignments.tid = task_id LIMIT 1);
		SET @lastname = (SELECT users.lastname FROM users INNER JOIN assignments ON assignments.id = users.id WHERE assignments.aid = assignment_id AND assignments.tid = task_id LIMIT 1);
        SET @assignment_action = (CASE @change_count WHEN 0 THEN 'REQUEST' ELSE 'CONFIRM' END);
        INSERT INTO changes (`tid`, `action`, `time`)
        VALUES (task_id, CONCAT(CONCAT(@firstname, ' ', @lastname), (CASE @assignment_action WHEN 'REQUEST' THEN ' requested to ' ELSE ' confirmed the request to ' END), LOWER(task_request), ' this task'), DATE_SUB(completed_date, INTERVAL (4 - @change_count - 1) DAY));

        SET @change_count = @change_count + 1;
    END LOOP add_complete;
	CLOSE assignment;
END$$
DELIMITER ;

DROP PROCEDURE IF EXISTS add_tasks;
DELIMITER $$
CREATE PROCEDURE add_tasks (new_amount INT)
BEGIN
	SET @task_amount = (SELECT COUNT(*) FROM tasks);
	SET @task_count = 1;
    WHILE @task_count <= new_amount DO
		SET @new_task_id = @task_count + @task_amount;
        SET @task_status = (CASE FLOOR(RAND()*2) WHEN 0 THEN 'COMPLETED' WHEN 1 THEN 'SKIPPED' END);
        SET @due_date = DATE_SUB(CURDATE(), INTERVAL (((2 * (new_amount - @task_count)) - 1) * 20) DAY);
        SET @completed_date = DATE_SUB(CURDATE(), INTERVAL ((2 * (new_amount - @task_count)) * 20) DAY);

        INSERT INTO tasks (`name`, `description`, `status`, `deadline`, `pid`, `completed`)
		VALUES (CONCAT('Task ', @new_task_id), CONCAT('Description ', @new_task_id), @task_status, @due_date, 2, @completed_date);
        SET @task_count = @task_count + 1;

        SET @task_request = (CASE @task_status WHEN 'COMPLETED' THEN 'SUBMIT' WHEN 'SKIPPED' THEN 'SKIP' END);

        INSERT INTO assignments (`id`, `tid`, `request`)
		VALUES (1, @new_task_id, @task_request), (4, @new_task_id, @task_request), (5, @new_task_id, @task_request), (7, @new_task_id, @task_request), (8, @new_task_id, @task_request);

        CALL add_history(@new_task_id, @task_request, @completed_date);
        CALL add_forms(@new_task_id);
	END WHILE;
END$$
DELIMITER ;

INSERT INTO users (`username`, `password`, `firstname`, `lastname`, `email`)
VALUES
	('test2', 'test2', 'John', 'Smith', 'a@mail.com'),
	('test3', 'test3', 'Jane', 'Doe', 'b@mail.com'),
	('passwordq', 'password3', 'Kevin', 'Spacy', 'c@mail.com'),
	('TheRealAlexJones', 'password3', 'Alex', 'Jones', 'a@infowars.com'),
	('twitterismine', 'password3', 'Elon', 'Musk', 'a@gmail.com'),
  ('lebron_james', 'password4', 'LeBron', 'James', 'd@mail.com'),
	('password', 'password', 'Joe', 'Biden', 'password@mail.com'),
	('im_dead_bruh', 'microsoft', 'Steve', 'Jobs', 'ajskd@mail.com');

INSERT INTO projects (`name`, `description`, `color`)
VALUES
	('CSC-330', 'Software Design and Development - Fall 2022', 'blue'),
	('My Project', 'My Description', 'purple'),
	('Flat Earth Association', 'If the earth is round, why does gravity pull things down?', 'emerald');

INSERT INTO roles (`rank`, `id`, `pid`)
VALUES
  ('Owner', 5, 1), ('Leader', 1, 1), ('Leader', 8, 1), ('Member', 2, 1), ('Member', 6, 1), ('Owner', 8, 2),
  ('Leader', 1, 2), ('Member', 7, 2), ('Member', 4, 2), ('Member', 5, 2), ('Owner', 1, 3), ('Member', 2, 3),
  ('Member', 3, 3), ('Member', 4, 3), ('Leader', 5, 3), ('Member', 6, 3), ('Member', 7, 3), ('Member', 8, 3);

INSERT INTO tasks (`name`, `description`, `status`, `deadline`, `pid`, `completed`)
VALUES
	('Create the Tin Foil Hat Society', 'Start an underground secret society (with tin foil hats)', 'COMPLETED', DATE_SUB(CURDATE(), INTERVAL 2 MONTH), 3, DATE_SUB(CURDATE(), INTERVAL 21 DAY)),
	('Expand the Tin Foil Hat Society', 'Expand our tin foil hat society even further', 'COMPLETED_LATE', DATE_SUB(CURDATE(), INTERVAL 1 MONTH), 3, DATE_SUB(CURDATE(), INTERVAL 20 DAY)),
  ('Find Amelia Earhart', 'where she at doe', 'IN_PROGRESS', DATE_SUB(CURDATE(), INTERVAL 13 YEAR), 3, null),
  ('task name', 'task description', 'IN_PROGRESS', DATE_ADD(CURDATE(), INTERVAL 7 DAY), 3, null),
	('Prove the Earth is Flat', 'read this to get trolled', 'NOT_STARTED', DATE_ADD(CURDATE(), INTERVAL 1 MONTH), 3, null),
  ('FlatEarthCon 2022', 'please do not invite any round earthers this year', 'NOT_STARTED', DATE_ADD(CURDATE(), INTERVAL 1 MONTH), 3, null),
  ('Sue NASA', 'They lied to millions of people about the moon landings', 'IN_PROGRESS', DATE_ADD(CURDATE(), INTERVAL 1 MONTH), 3, null),
  ('Im running out of funny task names oh no', 'What else do flat earth people believe', 'IN_PROGRESS', DATE_ADD(CURDATE(), INTERVAL 1 MONTH), 3, null);

INSERT INTO subtasks (`tid`, `name`, `description`, `status`, `deadline`, `completed`)
VALUES
	(3, 'Subtask 1', 'Subtask_description_1', 'COMPLETED', DATE_SUB(CURDATE(), INTERVAL 5 YEAR), DATE_SUB(CURDATE(), INTERVAL 6 YEAR)),
  (3, 'Subtask 2', 'Subtask_description_2', 'COMPLETED_LATE', DATE_SUB(CURDATE(), INTERVAL 4 YEAR), DATE_SUB(CURDATE(), INTERVAL 3 YEAR)),
  (3, 'Subtask 3', 'Subtask_description_3', 'SKIPPED', DATE_SUB(CURDATE(), INTERVAL 1 YEAR), DATE_SUB(CURDATE(), INTERVAL 2 YEAR)),
  (3, 'Subtask 4', 'Subtask_description_4', 'IN_PROGRESS', DATE_SUB(CURDATE(), INTERVAL 1 YEAR), null),
  (3, 'Subtask 5', 'Subtask_description_5', 'IN_PROGRESS', DATE_ADD(CURDATE(), INTERVAL 6 month), null),
  (3, 'Subtask 6', 'Subtask_description_6', 'NOT_STARTED', DATE_ADD(CURDATE(), INTERVAL 1 YEAR), null);

INSERT INTO assignments (`id`, `tid`, `request`)
VALUES
	(3, 1, 'SUBMIT'), (4, 1, 'SUBMIT'), (7, 1, 'SUBMIT'),
  (3, 2, 'SUBMIT'), (5, 2, 'SUBMIT'), (6, 2, 'SUBMIT'), (7, 2, 'SUBMIT'),
	(3, 3, 'SUBMIT'), (4, 3, 'SUBMIT'), (5, 3, 'SUBMIT'),
  (3, 4, 'SKIP'), (4, 4, null), (6, 4, 'SKIP'),
  (3, 5, null), (4, 5, null), (5, 5, null), (7, 5, null),
  (3, 6, 'START'), (4, 6, null), (6, 6, 'START'),
  (3, 7, 'SKIP'), (4, 7, null), (6, 7, 'SKIP'),
  (3, 8, 'SUBMIT'), (4, 8, null), (6, 8, 'SUBMIT');

CALL add_history(1, 'SUBMIT', DATE_SUB(CURDATE(), INTERVAL 21 DAY));
CALL add_history(1, 'SUBMIT', DATE_SUB(CURDATE(), INTERVAL 20 DAY));
CALL add_forms(1);
CALL add_forms(2);

INSERT INTO changes (`tid`, `action`, `time`)
VALUES
	(3, 'Kevin Spacy requested to start this task', DATE_SUB(CURDATE(), INTERVAL 30 DAY)),
  (3, 'Alex Jones confirmed the request to start this task', DATE_SUB(DATE_SUB(CURDATE(), INTERVAL 29 DAY), INTERVAL 12 HOUR)),
  (3, 'Elon Musk confirmed the request to start this task', DATE_SUB(CURDATE(), INTERVAL 29 DAY)),
	(3, 'Kevin Spacy requested to submit this task', DATE_SUB(CURDATE(), INTERVAL 27 DAY)),
  (3, 'Alex Jones confirmed the request to submit this task', DATE_SUB(DATE_SUB(CURDATE(), INTERVAL 26 DAY), INTERVAL 12 HOUR)),
  (3, 'Elon Musk denied the request to submit this task', DATE_SUB(CURDATE(), INTERVAL 26 DAY)),
	(3, 'Kevin Spacy requested to skip this task', DATE_SUB(CURDATE(), INTERVAL 24 DAY)),
  (3, 'Alex Jones confirmed the request to skip this task', DATE_SUB(DATE_SUB(CURDATE(), INTERVAL 23 DAY), INTERVAL 12 HOUR)),
  (3, 'Elon Musk denied the request to skip this task', DATE_SUB(CURDATE(), INTERVAL 23 DAY)),
	(3, 'Elon Musk requested to submit this task', DATE_SUB(CURDATE(), INTERVAL 22 DAY)),
	(3, 'Kevin Spacy confirmed the request to submit this task', DATE_SUB(DATE_SUB(CURDATE(), INTERVAL 21 DAY), INTERVAL 12 HOUR)),
  (3, 'Alex Jones confirmed the request to submit this task', DATE_SUB(CURDATE(), INTERVAL 21 DAY)),
	(6, 'Kevin Spacy requested to start this task', DATE_SUB(CURDATE(), INTERVAL 27 DAY)),
	(6, 'LeBron	James confirmed the request to start this task', DATE_SUB(DATE_SUB(CURDATE(), INTERVAL 26 DAY), INTERVAL 12 HOUR)),
	(7, 'Kevin Spacy requested to skip this task', DATE_SUB(CURDATE(), INTERVAL 26 DAY)),
	(7, 'LeBron	James confirmed the request to skip this task', DATE_SUB(DATE_SUB(CURDATE(), INTERVAL 25 DAY), INTERVAL 12 HOUR)),
	(8, 'Kevin Spacy requested to start this task', DATE_SUB(CURDATE(), INTERVAL 23 DAY)),
	(8, 'Alex Jones confirmed the request to start this task', DATE_SUB(DATE_SUB(CURDATE(), INTERVAL 22 DAY), INTERVAL 18 HOUR)),
	(8, 'LeBron	James confirmed the request to start this task', DATE_SUB(DATE_SUB(CURDATE(), INTERVAL 22 DAY), INTERVAL 12 HOUR)),
	(8, 'Kevin Spacy requested to submit this task', DATE_SUB(CURDATE(), INTERVAL 21 DAY)),
	(8, 'LeBron	James confirmed the request to submit this task', DATE_SUB(DATE_SUB(CURDATE(), INTERVAL 20 DAY), INTERVAL 12 HOUR));


CALL add_tasks(25);

INSERT INTO messages (`id`, `id2`, `subject`, `content`, `status`, `date`)
VALUES
	(3, 4, 'TEST 1', 'test message 1 test message 1 test message 1 test message 1 test message 1 test message 1 test message 1 test message 1', 'UNREAD', DATE_SUB(CURDATE(), INTERVAL 7 DAY)),
	(3, 4, 'TEST 2', 'test message 2 test message 2 test message 2 test message 2 test message 2 test message 2 test message 2 test message 2', 'READ', DATE_SUB(CURDATE(), INTERVAL 6 DAY)),
	(3, 4, 'TEST 3', 'test message 3 test message 3 test message 3 test message 3 test message 3 test message 3 test message 3 test message 3', 'UNREAD', DATE_SUB(CURDATE(), INTERVAL 5 DAY)),
	(3, 4, 'TEST 4', 'test message 4 test message 4 test message 4 test message 4 test message 4 test message 4 test message 4 test message 4', 'UNREAD', DATE_SUB(CURDATE(), INTERVAL 4 DAY)),
	(4, 3, 'TEST 5', 'test message 5 test message 5 test message 5 test message 5 test message 5 test message 5 test message 5 test message 5', 'READ', DATE_SUB(CURDATE(), INTERVAL 3 DAY)),
	(4, 3, 'TEST 6', 'test message 6 test message 6 test message 6 test message 6 test message 6 test message 6 test message 6 test message 6', 'UNREAD', DATE_SUB(CURDATE(), INTERVAL 2 DAY)),
	(4, 3, 'TEST 7', 'test message 7 test message 7 test message 7 test message 7 test message 7 test message 7 test message 7 test message 7', 'UNREAD', DATE_SUB(CURDATE(), INTERVAL 1 DAY));
