<?php
// Login insert username and password
//need to make sure login can't be done multiple time in succession because multiple authorization tokens will be created!!!
$app->post('/login', function ($request, $response) {
	$authorization = $request->getHeader('Authorization');
        $authorization = implode(" ",$authorization);
        $input = $request->getParsedBody();
        $view;
        $sql = "SELECT * FROM `Users` WHERE `Users`.email = :email";
        $sth = $this->db->prepare($sql);
        $sth->bindParam(":email", $input['email']);
        $sth->execute();
        $token  = bin2hex(openssl_random_pseudo_bytes(16));
        if( $sth->rowCount() == 0){
                $view['error'] = "bad request";
                $view['message'] = "No user found";
                $input['error']="bad request";
                $input['message']="No User Found";
        }
        else {
                $sql = "SELECT id FROM `Users` WHERE email = :email";
                $sth = $this->db->prepare($sql);
                $sth->bindParam(":email", $input['email']);
                $sth->execute();
                $id = $sth->fetchColumn(0);
                $input['id'] = $id;
                $sql = "SELECT password FROM `Users` WHERE email = :email";
                $sth = $this->db->prepare($sql);
                $sth->bindParam(":email", $input['email']);
                $sth->execute();
                $dbpass = $sth->fetchColumn(0);
                //$input['dbpass'] = $dbpass;
                //$input['id'] = implode(" ",$id);
                $inpass = $input['password'];

                if(password_verify($inpass, $dbpass)){
                        //check if already logged in
                        $sql = "SELECT * FROM `Web Sessions` WHERE id = :id AND authorization IS NOT NULL";
                        $sth = $this->db->prepare($sql);
                        $sth->bindParam(":id", $id);
                        $sth->execute();
                        if($sth->rowCount() != 0){
                                $view['error'] = "You are already logged in.";
                                $input['error'] = "You are already logged in.";
				$newResponse = $this->response->withAddedHeader("Authorization", $authorization);
				return $newResponse->withJson($view);
                        }
                        else{
                                $input['success'] = "logged in";
                                $view['success'] = "logged in";
                                $sql = "INSERT INTO `Web Sessions`(`id`,`authorization`) VALUES (:id, :token)";
                                $sth = $this->db->prepare($sql);
                                $sth->bindParam(":id", $id);
                                $sth->bindParam(":token", $token);
                                $sth->execute();
                                $newResponse = $this->response->withAddedHeader("Authorization", $token);
                                //return $newResponse->withJson($input);
                                return $newResponse->withJson($view);
                        }
                }
                else{
                        $input['failure'] = "password is wrong";
                        $view['failure'] = "password is wrong";
                }
        }
        //return $this->response->withJson($input);
        return $this->response->withJson($view);
});

$app->post('/student/signup', function ($request, $response) {
        $input = $request->getParsedBody();
        $view;
        $token  = bin2hex(openssl_random_pseudo_bytes(16));
        $sql = "SELECT * FROM `Users` WHERE email = :email";
        $sth = $this->db->prepare($sql);
        $sth->bindParam(":email", $input['email']);
        $sth->execute();
        if($sth->rowCount() == 0) {
                $sql = "INSERT INTO `Users`(`first_name`, `last_name`, `email`, `password`) VALUES (:first_name,:last_name,:email,:password)";
                $sth = $this->db->prepare($sql);
                $sth->bindParam(":email", $input['email']);
                $sth->bindParam(":first_name", $input['first_name']);
                $sth->bindParam(":last_name", $input['last_name']);
                $sth->bindParam(":password", password_hash($input['password'],PASSWORD_DEFAULT,['cost' => 15]));
                $sth->execute();
                $lastId = $this->db->lastInsertId();
                $sql = "INSERT INTO `Students`(`first_name`, `last_name`, `email`, `password`, `student_id`) VALUES (:first_name,:last_name,:email,:password,:lastId)";
                $sth = $this->db->prepare($sql);
                $sth->bindParam(":email", $input['email']);
                $sth->bindParam(":first_name", $input['first_name']);
                $sth->bindParam(":last_name", $input['last_name']);
                $sth->bindParam(":password",password_hash($input['password'], PASSWORD_DEFAULT, ['cost' => 15]));
                $sth->bindParam(":lastId", $lastId);
                $sth->execute();
                $input['email'] = $this->db->lastInsertId();
                $input['first_name'] = $this->db->lastInsertId();
                $input['last_name'] = $this->db->lastInsertId();
                $input['password'] = $this->db->lastInsertId();
                //immediately log the new user in
                $sql = "INSERT INTO `Web Sessions` (`id`, `authorization`) VALUES (:id, :token)";
                $sth = $this->db->prepare($sql);
		$token  = bin2hex(openssl_random_pseudo_bytes(16));
                $sth->bindParam(":token", $token);
                $sth->bindParam(":id", $lastId);
                $sth->execute();
                $newResponse = $this->response->withAddedHeader("Authorization", $token);
                return $newResponse->withJson($input);
        }
        else{
                $view['error'] = "A user with this email already exists.";
        }
        return $this->response->withJson($view);
        //$newResponse = $this->response->withAddedHeader("Authorization", $token);
        //return $newResponse->withJson($input);
});

//tutor sign up
//email duplicates are accounted for 
$app->post('/tutor/signup', function ($request, $response) {
        $input = $request->getParsedBody();
        $view;
        $token  = bin2hex(openssl_random_pseudo_bytes(16));
        $sql = "SELECT * FROM `Users` WHERE email = :email";
        $sth = $this->db->prepare($sql);
        $sth->bindParam(":email", $input['email']);
        $sth->execute();
        if($sth->rowCount() == 0) {
                $sql = "INSERT INTO `Users`(`first_name`, `last_name`, `email`, `password`) VALUES (:first_name,:last_name,:email,:password)";
                $sth = $this->db->prepare($sql);
                $sth->bindParam(":email", $input['email']);
                $sth->bindParam(":first_name", $input['first_name']);
                $sth->bindParam(":last_name", $input['last_name']);
                $sth->bindParam(":password", password_hash($input['password'],PASSWORD_DEFAULT,['cost' => 15]));
                $sth->execute();
                $lastId = $this->db->lastInsertId();
                $sql = "INSERT INTO `Tutors`(`first_name`, `last_name`, `email`, `password`, `tutor_id`) VALUES (:first_name,:last_name,:email,:password, :lastId)";
                $sth = $this->db->prepare($sql);
                $sth->bindParam(":email", $input['email']);
                $sth->bindParam(":first_name", $input['first_name']);
                $sth->bindParam(":last_name", $input['last_name']);
                $sth->bindParam(":password", password_hash($input['password'], PASSWORD_DEFAULT,['cost' => 15]));
                $sth->bindParam(":lastId", $lastId);
                $sth->execute();
                $input['first_name'] = $this->db->lastInsertId();
                $input['last_name'] = $this->db->lastInsertId();
                $input['password'] = $this->db->lastInsertId();
                $input['email'] = $this->db->lastInsertId();
                //immediately log the new user in
                $sql = "INSERT INTO `Web Sessions` (`id`, `authorization`) VALUES (:id, :token)";
                $sth = $this->db->prepare($sql);
                $token  = bin2hex(openssl_random_pseudo_bytes(16));
		$sth->bindParam(":token", $token);
                $sth->bindParam(":id", $lastId);
                $sth->execute();
                $newResponse = $this->response->withAddedHeader("Authorization", $token);
                return $newResponse->withJson($input);
        }
        else {
                $view['error'] = "A user with that email already exists.";
        }
         return $this->response->withJson($view);
         //$newResponse = $this->response->withAddedHeader("Authorization", $token);
         //return $newResponse->withJson($input);
});

//logout
$app->post('/logout', function ($request, $response) {
        $authorization = $request->getHeader('Authorization');
        $authorization = implode(" ",$authorization);
        $input = $request->getParsedBody();
        $view;
        $sql = "SELECT authorization FROM `Web Sessions` WHERE authorization = :authorization";
        $sth = $this->db->prepare($sql);
        $sth->bindParam(":authorization", $authorization);
        $sth->execute();
        if($sth->rowCount() != 0 ){
                $sql = "UPDATE `Web Sessions` SET `logout_time` = CURRENT_TIMESTAMP WHERE authorization = :authorization";
                $sth = $this->db->prepare($sql);
                $sth->bindParam(":authorization", $authorization);
                $sth->execute();
                $view['logout_time'] = CURRENT_TIMESTAMP;
                //$input['logout_time'] = CURRENT_TIMESTAMP;
                //Delete Authorization key / session
                $sql = "UPDATE `Web Sessions` SET `authorization`= NULL WHERE authorization = :authorization";
                $sth = $this->db->prepare($sql);
                $sth->bindParam(":authorization", $authorization);
                $sth->execute();
                //$input['Success'] = "Successfully logged out";
                $view['Success'] = "Successfully logged out";
        }
        else{
                //$input['Failure'] = "Error: Action not authorized";
                $view['Failure'] = "Error: Action not authorized";
        }
       //return $this->response->withJson($input);
        return $this->response->withJson($view);
});        


$app->post('/uploadpic', function ($request, $response) {
        $input = $request->getParsedBody();
        $files = $request->getUploadedFiles();
        $sql = "INSERT INTO `Photos` (`name`, `photo`) VALUES (:image_name, :image)";
        $sth = $this->db->prepare($sql);
        $sth->bindParam(":image_name", $input['image_name']);
        $sth->bindParam(":image", $files);
        $sth->execute();
        return $this->response->withJson($view);

});

//create sessions
$app->post('/requestsession', function ($request, $response) {
        $input = $request->getParsedBody();
        //get authorization token and user id 
        $authArray = $request->getHeader('Authorization');
        $auth = implode(" ", $authArray);
        $sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
        $sth = $this->db->prepare($sql);
        $sth->bindParam(":auth", $auth);
        $sth->execute();

        //Retrieve the ID from the resulting SQL statment
        $sth->setFetchMode(PDO::FETCH_ASSOC);
        $row = $sth->fetch();
        $id = $row["id"];

        //If there was no id found, return an error
        if (empty($id)) {
                $input['Failure'] = "Action not authorized";
        }
        else {
                //get course id by requested course name
                $sql = "SELECT course_id FROM `Courses` WHERE course_name = :course_name";
                $sth = $this->db->prepare($sql);
                $sth->bindParam(":course_name", $input['course_name']);
                $sth->execute();
                $course_id = $sth->fetchColumn(0);
                $input['course_id'] = $course_id;
                
                //check if course is offered by seeing if course id is in course table
                if(empty($course_id)){
                        $input["Failure"] = "Couse does not exist";
                }
                else{
                        //check if tutor with inputed tutor id even exists
                        $sql = "SELECT * FROM `Tutors` WHERE tutor_id = :tutor_id";
                        $sth = $this->db->prepare($sql);
                        $sth->bindParam(":tutor_id", $input['tutor_id']);
                        $sth->execute();

                        if($sth->rowCount() == 0){
                                $input["Failure"] = "Tutor does not exist";
                        }
                        else{ 
                                //now create a session with the tutor id, student id, course id, and timestamp
                                $sql = "INSERT INTO `Sessions` (`tutor_id`, `student_id`, `course_id`) 
                                        VALUES (:tutor_id ,:student_id, :course_id)";
                                $sth = $this->db->prepare($sql);
                                $sth->bindParam(":tutor_id", $input['tutor_id']);
                                $sth->bindParam(":student_id", $id);
                                $sth->bindParam(":course_id", $course_id);
                                $sth->execute();
                                $input['success'] = "Session successfully requested.";
                                $newResponse = $this->response->withAddedHeader("Authorization", $auth);
                                return $newResponse->withJson($input);
                        }
                }
        }

        //$newResponse = $this->response->withAddedHeader("Authorization", $auth);
        //return $newResponse->withJson($input);
        return $this->response->withJson($input);
});

$app->post('/acceptsession', function ($request, $response) {
        $input = $request->getParsedBody();
        //get authorization token and user id 
        $authArray = $request->getHeader('Authorization');
        $auth = implode(" ", $authArray);
        $sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
        $sth = $this->db->prepare($sql);
        $sth->bindParam(":auth", $auth);
        $sth->execute();
        $input['auth'] = $auth;
        //Retrieve the ID from the resulting SQL statment
        $sth->setFetchMode(PDO::FETCH_ASSOC);
        $row = $sth->fetch();
        $id = $row["id"];
        $input['id'] = $id;

        //If there was no id found, return an error
        if (empty($id)) {
                $input["Failure"] = "Action not authorized";
        }
        else {
                //gives failure message if session does not exist
                $sql = "SELECT * FROM `Sessions` WHERE `tutor_id` = :tutor_id AND `student_id` = :student_id AND `course_id` = :course_id";
                $sth = $this->db->prepare($sql);
                $sth->bindParam(":tutor_id", $id);
                $sth->bindParam(":student_id", $input['student_id']);
                $sth->bindParam(":course_id", $input['course_id']);
                $sth->execute();
                if($sth->rowCount() == 0){
                        $input['Failure'] = "Cannot accept session because it doesn't exist.";
                }

                //set is accepted to 1 and add the time
                $sql = "UPDATE `Sessions` SET `isAccepted`= 1 
                        WHERE `tutor_id` = :tutor_id AND `student_id` = :student_id AND `course_id` = :course_id";
                $sth = $this->db->prepare($sql);
                $sth->bindParam(":tutor_id", $id);
                $sth->bindParam(":student_id", $input['student_id']);
                $sth->bindParam(":course_id", $input['course_id']);
                $sth->execute();
                $sql = "UPDATE `Sessions` SET `time_accepted`= CURRENT_TIMESTAMP 
                        WHERE `tutor_id` = :tutor_id AND `student_id` = :student_id AND `course_id` = :course_id";
                $sth = $this->db->prepare($sql);
                $sth->bindParam(":tutor_id", $id);
                $sth->bindParam(":student_id", $input['student_id']);
                $sth->bindParam(":course_id", $input['course_id']);
                $sth->execute();
                $newResponse = $this->response->withAddedHeader("Authorization", $auth);
                return $newResponse->withJson($input);
        }

        //$newResponse = $this->response->withAddedHeader("Authorization", $auth);
        //return $newResponse->withJson($input);
        return $this->response->withJson($input);
});


$app->post('/ratesession', function ($request, $response) {
        $input = $request->getParsedBody();
        //get authorization token and user id 
        $authArray = $request->getHeader('Authorization');
        $auth = implode(" ", $authArray);
        $sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
        $sth = $this->db->prepare($sql);
        $sth->bindParam(":auth", $auth);
        $sth->execute();
        $rating_receiver = NULL;
        
        $input["check"] = $input['tutor_id'];
        //Retrieve the ID from the resulting SQL statment
        $sth->setFetchMode(PDO::FETCH_ASSOC);
        $row = $sth->fetch();
        $id = $row["id"];
        $input['id'] = $id;

        //If there was no id found in Web Sessions, return an error
        //User is not logged in
        if (empty($id)) {
                $input['Failure'] = "Action not authorized";
        }
        else {
                //check if the session even exists between the student, tutor, and course and checks if it has been accepted
                $sql = "SELECT * FROM `Sessions` WHERE `tutor_id` = :tutor_id AND `student_id` = :student_id AND `course_id` = :course_id AND `isAccepted` = 1";
                $sth = $this->db->prepare($sql);
                $sth->bindParam(":tutor_id", $input['tutor_id']);
                $sth->bindParam(":student_id", $input['student_id']);
                $sth->bindParam(":course_id", $input['course_id']);
                $sth->execute();
                $session = $sth->fetchAll();
                if(empty($session))
                {
                        $input['error']= "Cannot give session rating. Session does not exist.";
                }
                else{
                        //check if the user is a tutor or student
                        $sql = "SELECT * FROM `Tutors` WHERE `tutor_id` = :tutor_id";
                        $sth = $this->db->prepare($sql);
                        $sth->bindParam(":tutor_id", $id);
                        $sth->execute();
                        $sth->setFetchMode(PDO::FETCH_ASSOC);
                        $row = $sth->fetch();
                        $tutor_id = $row["tutor_id"];
                        //User is not a tutor, so check if user is a student
                        if (empty($tutor_id)) {
                                $sql = "SELECT * FROM `Students` WHERE `student_id` = :student_id";
                                $sth = $this->db->prepare($sql);
                                $sth->bindParam(":student_id", $id);
                                $sth->execute();
                                $sth->setFetchMode(PDO::FETCH_ASSOC);
                                $row = $sth->fetch();
                                $student_id = $row["student_id"];
                                if (empty($student_id)) {
                                        $input['Failure'] = "Action not authorized";
                                }
                                //user is a student
                                else{
                                        //check if user is giving a valid rating (it must be between 1-5); if user gives invalid input, rating_value is blank in table
                                        if($input['rating_value'] <= 5 and $input['rating_value'] >= 1){
                                                $rating_receiver = "Tutor";
                                                //check if session has already been given a rating
                                                //if yes, update rating instead of creating a new rating
                                                $rating_receiver = "Tutor";
                                                $sql = "SELECT * FROM `Ratings` WHERE `tutor_id` = :tutor_id 
                                                        AND `student_id` = :student_id
                                                        AND `course_id` = :course_id
                                                        AND `rating_receiver` = :rating_receiver";
                                                $sth = $this->db->prepare($sql);
                                                $sth->bindParam(":tutor_id", $input['tutor_id']);
                                                $sth->bindParam(":student_id", $input['student_id']);
                                                $sth->bindParam(":course_id", $input['course_id']);
                                                $sth->bindParam(":rating_receiver", $rating_receiver);
                                                $sth->execute();
                                                
                                                //no duplicate session rating exists
                                                if($sth->rowCount() == 0){
                                                        $sql = "INSERT INTO `Ratings` (`tutor_id`, `student_id`, `course_id`,`rating_receiver`, `rating_value`) 
                                                                VALUES (:tutor_id, :student_id, :course_id, :rating_receiver, :rating_value) ";
                                                        $sth = $this->db->prepare($sql);
                                                        $sth->bindParam(":tutor_id",$input['tutor_id']);
                                                        $sth->bindParam(":student_id",$input['student_id']);
                                                        $sth->bindParam(":course_id", $input['course_id']);
                                                        $sth->bindParam(":rating_receiver", $rating_receiver);
                                                        $sth->bindParam(":rating_value", $input['rating_value']);
                                                        $sth->execute();
                                                }
                                                else{
                                                        $sql = "UPDATE `Ratings` SET `rating_value` = :rating_value 
                                                                WHERE `tutor_id` = :tutor_id
                                                                AND `student_id` = :student_id
                                                                AND `course_id` = :course_id
                                                                AND `rating_receiver` = :rating_receiver";
                                                        $sth = $this->db->prepare($sql);
                                                        $sth->bindParam(":tutor_id",$input['tutor_id']);
                                                        $sth->bindParam(":student_id",$input['student_id']);
                                                        $sth->bindParam(":course_id", $input['course_id']);
                                                        $sth->bindParam(":rating_receiver", $rating_receiver);
                                                        $sth->bindParam(":rating_value", $input['rating_value']);
                                                        $sth->execute();
                                                }

                                                $input['success'] = "Success. You have given the tutor a rating of " . $input['rating_value'];
                                                $newResponse = $this->response->withAddedHeader("Authorization", $auth);
                                                return $newResponse->withJson($input);
                                        }
                                        else{
                                                $input['error'] = "Invalid rating. Rating must be between 1-5.";
                                        }
                                }
                        }
                        //User is a tutor so insert their rating of the student into Ratings table
                        else{
                                //check if user is giving a valid rating (it must be between 1-5); if user gives invalid input, rating_value is blank in table
                                if($input['rating_value'] <= 5 and $input['rating_value'] >= 1){
                                        $rating_receiver = "Student";
                                        $sql = "SELECT * FROM `Ratings` WHERE `tutor_id` = :tutor_id 
                                                        AND `student_id` = :student_id
                                                        AND `course_id` = :course_id
                                                        AND `rating_receiver` = :rating_receiver";
                                        $sth = $this->db->prepare($sql);
                                        $sth->bindParam(":tutor_id", $input['tutor_id']);
                                        $sth->bindParam(":student_id", $input['student_id']);
                                        $sth->bindParam(":course_id", $input['course_id']);
                                        $sth->bindParam(":rating_receiver", $rating_receiver);
                                        $sth->execute();
                                        
                                        if($sth->rowCount() == 0){
                                                $sql = "INSERT INTO `Ratings` (`tutor_id`, `student_id`, `course_id`,`rating_receiver`, `rating_value`) 
                                                        VALUES (:tutor_id, :student_id, :course_id, :rating_receiver, :rating_value) ";
                                                $sth = $this->db->prepare($sql);
                                                $sth->bindParam(":tutor_id",$input['tutor_id']);
                                                $sth->bindParam(":student_id",$input['student_id']);
                                                $sth->bindParam(":course_id", $input['course_id']);
                                                $sth->bindParam(":rating_receiver", $rating_receiver);
                                                $sth->bindParam(":rating_value", $input['rating_value']);
                                                $sth->execute();
                                        }
                                        else{
                                                $sql = "UPDATE `Ratings` SET `rating_value` = :rating_value 
                                                                WHERE `tutor_id` = :tutor_id
                                                                AND `student_id` = :student_id
                                                                AND `course_id` = :course_id
                                                                AND `rating_receiver` = :rating_receiver";
                                                        $sth = $this->db->prepare($sql);
                                                        $sth->bindParam(":tutor_id",$input['tutor_id']);
                                                        $sth->bindParam(":student_id",$input['student_id']);
                                                        $sth->bindParam(":course_id", $input['course_id']);
                                                        $sth->bindParam(":rating_receiver", $rating_receiver);
                                                        $sth->bindParam(":rating_value", $input['rating_value']);
                                                        $sth->execute();
                                        }

                                        $input['success'] = "Success. You have given the student a rating of " . $input['rating_value'];
                                        $newResponse = $this->response->withAddedHeader("Authorization", $auth);
                                        return $newResponse->withJson($input);
                                }
                                else{
                                        $input['error'] = "Invalid rating. Rating must be between 1-5.";
                                }
                        }
                }
        }
        return $this->response->withJson($input);

});    

//Add the remaining tutor information
$app->post('/tutor/newProfile', function ($request, $response) {
	//Retrieve the authorization token and get the id of the active user
	$authArray = $request->getHeader('Authorization');
	$input = $request->getParsedBody();
	$auth = implode(" ", $authArray);
	$sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
	$sth = $this->db->prepare($sql);
	$sth->bindParam(":auth", $auth);
	$sth->execute();

	//Retrieve the ID from the resulting SQL statment
	$sth->setFetchMode(PDO::FETCH_ASSOC);
	$row = $sth->fetch();
	$id = $row["id"];

	//If there was no id found, return an error
	if (empty($id)) {
		$input["Login Error"] = "The user is not logged in";
	}
	else {
		$sql = "UPDATE `Tutors` SET bio = :bio, past_high_school = :past_high_school WHERE tutor_id = :id";
    		$sth = $this->db->prepare($sql);
    		$sth->bindParam(":bio", $input['bio']);
		$sth->bindParam(":id", $id);
    		$sth->bindParam(":past_high_school", $input['past_high_school']);
    		$sth->execute();
    		$input['bio'] = $this->db->lastInsertId();
		$input['past_high_school'] = $this->db->lastInsertId();
	}
	$newResponse = $this->response->withAddedHeader("Authorization", $auth);
	return $newResponse->withJson($input);
});

//Add the remaining student informatin
$app->post('/student/newProfile', function ($request, $response) {
	//Retrieve the authorization token and get the id of the active user
	$authArray = $request->getHeader('Authorization');
	$input = $request->getParsedBody();
	$auth = implode(" ", $authArray);
	$sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
	$sth = $this->db->prepare($sql);
	$sth->bindParam(":auth", $auth);
	$sth->execute();

	//Retrieve the ID from the resulting SQL statment
	$sth->setFetchMode(PDO::FETCH_ASSOC);
	$row = $sth->fetch();
	$id = $row["id"];

	//If there was no id found, return an error
	if (empty($id)) {
		$input["Login Error"] = "The user is not logged in";
	}
	else {
		$sql = "UPDATE `Students` SET bio = :bio, high_school = :high_school, graduation_year = :graduation_year  WHERE student_id = :id";
    		$sth = $this->db->prepare($sql);
    		$sth->bindParam(":bio", $input['bio']);
		$sth->bindParam(":id", $id);
    		$sth->bindParam(":high_school", $input['high_school']);
		$sth->bindParam(":graduation_year", $input['graduation_year']);
    		$sth->execute();
    		$input['bio'] = $this->db->lastInsertId();
		$input['past_high_school'] = $this->db->lastInsertId();
	}
	$newResponse = $this->response->withAddedHeader("Authorization", $auth);
	return $newResponse->withJson($input);
});

//View Tutor Profile
$app->get('/tutor/viewProfile', function ($request, $response, $args) {
	$authArray = $request->getHeader('Authorization');
	$input = $request->getParsedBody();
	$auth = implode(" ", $authArray);
	$sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
	$sth = $this->db->prepare($sql);
	$sth->bindParam(":auth", $auth);
	$sth->execute();
	//Retrieve the ID from the resulting SQL statment
	$sth->setFetchMode(PDO::FETCH_ASSOC);
	$row = $sth->fetch();
	$tutor_id = $row["id"];
	//If there was no id found, return an error
	if (empty($tutor_id)) {
		$input["Login Error"] = "The user is not logged in";
	}
	else {
		$sth = $this->db->prepare("SELECT first_name, last_name, past_high_school, bio FROM `Tutors` WHERE tutor_id=:tutor_id");
		$sth->bindParam("tutor_id",$tutor_id);
		$sth->execute();
		$view = $sth->fetchObject();
		return $this->response->withJson($view);
		
	}
	$newResponse = $this->response->withAddedHeader("Authorization", $auth);
	return $newResponse->withJson($input);
});
//View Student Profile
$app->get('/student/viewProfile', function ($request, $response, $args) {
	$authArray = $request->getHeader('Authorization');
	$input = $request->getParsedBody();
	$auth = implode(" ", $authArray);
	$sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
	$sth = $this->db->prepare($sql);
	$sth->bindParam(":auth", $auth);
	$sth->execute();
	//Retrieve the ID from the resulting SQL statment
	$sth->setFetchMode(PDO::FETCH_ASSOC);
	$row = $sth->fetch();
	$student_id = $row["id"];
	//If there was no id found, return an error
	if (empty($student_id)) {
		$input["Login Error"] = "The user is not logged in";
	}
	else {
		$sth = $this->db->prepare("SELECT first_name, last_name, high_school, graduation_year, bio FROM `Students` JOIN `Photos`  WHERE student_id = :student_id AND id = student_id");
		$sth->bindParam("student_id",$args['student_id']);
		$sth->execute();
		$view = $sth->fetchObject();
		return $this->response->withJson($view);
	}
	$newResponse = $this->response->withAddedHeader("Authorization", $auth);
	return $newResponse->withJson($input);
});
//View Sessions From Tutor POV
$app->get('/tutor/sessions', function ($request, $response, $args) {
	$authArray = $request->getHeader('Authorization');
	$input = $request->getParsedBody();
	$auth = implode(" ", $authArray);
	$sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
	$sth = $this->db->prepare($sql);
	$sth->bindParam(":auth", $auth);
	$sth->execute();
	//Retrieve the ID from the resulting SQL statment
	$sth->setFetchMode(PDO::FETCH_ASSOC);
	$row = $sth->fetch();
	$tutor_id = $row["id"];
	//If there was no id found, return an error
	if (empty($tutor_id)) {
		$input["Login Error"] = "The user is not logged in";
	}
	else {   
		$sth = $this->db->prepare("SELECT first_name, last_name, bio, isAccepted, time_requested, time_accepted FROM `Sessions` NATURAL JOIN `Students` WHERE tutor_id =  :tutor_id");
		$sth->bindParam("tutor_id",$tutor_id);
		$sth->execute();
		$sessions = $sth->fetchAll();
		return $this->response->withJson($sessions);
	}
	$newResponse = $this->response->withAddedHeader("Authorization", $auth);
	return $newResponse->withJson($input);
});
//View Sessions From Student POV
$app->get('/student/sessions', function ($request, $response, $args) {
	$authArray = $request->getHeader('Authorization');
	$input = $request->getParsedBody();
	$auth = implode(" ", $authArray);
	$sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
	$sth = $this->db->prepare($sql);
	$sth->bindParam(":auth", $auth);
	$sth->execute();
	//Retrieve the ID from the resulting SQL statment
	$sth->setFetchMode(PDO::FETCH_ASSOC);
	$row = $sth->fetch();
	$student_id = $row["id"];
	//If there was no id found, return an error
	if (empty($student_id)) {
		$input["Login Error"] = "The user is not logged in";
	}
	else {
		$sth = $this->db->prepare("SELECT first_name, last_name, bio, isAccepted, time_requested, time_accepted FROM `Sessions` NATURAL JOIN `Tutors` WHERE student_id = :student_id");
		$sth->bindParam("student_id", $student_id);
		$sth->execute();
		$sessions = $sth->fetchAll();
   		return $this->response->withJson($sessions);
	}
	$newResponse = $this->response->withAddedHeader("Authorization", $auth);
	return $newResponse->withJson($input);
});
//Find Tutor
$app->get('/findTutor/{params:.*}', function ($request, $response, $args) {
   $params = explode('/', $request->getAttribute('params'));
   $subject_name = $params[0];
   $course_name = $params[1];
   $past_high_school = $params[2];
   if (empty($subject_name)) {
   	$subject_name = '%%';
   }
   if (empty($course_name)) {
   	$course_name = '%%';
   }
   if (empty($past_high_school)) {
   	$past_high_school = '%%';
   }
   $sth = $this->db->prepare("SELECT DISTINCT first_name, last_name, past_high_school, bio, photo FROM `Courses` NATURAL JOIN `Course Subjects` NATURAL JOIN `Subjects` NATURAL JOIN `Courses Taught` NATURAL JOIN `Tutors` JOIN `Photos`  WHERE subject_name LIKE :subject_name AND course_name LIKE :course_name AND past_high_school LIKE :past_high_school AND `Tutors`.tutor_id = `Photos`.id");
   $sth->bindParam("subject_name", $subject_name);
   $sth->bindParam("course_name", $course_name);
   $sth->bindParam("past_high_school", $past_high_school);
   $sth->execute();
   $find = $sth->fetchAll();
   $find['subject_name'] = $subject_name;
   $find['course_name'] = $course_name;
   $find['past_high_school'] = $past_high_school;
   return $this->response->withJson($find);
});
$app->get('/alltutors', function ($request, $response, $args) {
   $sth = $this->db->prepare("SELECT first_name, last_name, past_high_school, email  FROM `Tutors`");
   $sth->execute();
   $results = $sth->fetchAll();
   return $this->response->withJson($results);
});

//Edit courses

//Retrieve courses taught by a tutor
$app->get('/tutor/editCourse', function($request, $response, $args) {
	//Retrieve the authorization token and get the id of the active user
	$authArray = $request->getHeader('Authorization');
	$auth = implode(" ", $authArray);
	$sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
	$sth = $this->db->prepare($sql);
	$sth->bindParam(":auth", $auth);
	$sth->execute();

	//Retrieve the ID from the resulting SQL statment
	$sth->setFetchMode(PDO::FETCH_ASSOC);
	$row = $sth->fetch();
	$id = $row["id"];

	//If there was no id found, return an error
	if (empty($id)) {
		$find["Login Error"] = "The user is not logged in";
	}
	else {
		$sth = $this->db->prepare("SELECT course_name, course_id FROM `Courses Taught` NATURAL JOIN `Courses` WHERE tutor_id = :tutor_id");
		$sth->bindParam("tutor_id", $id);
		$sth->execute();
		$find = $sth->fetchAll();
	}
	$newResponse = $this->response->withAddedHeader("Authorization", $auth);
	return $newResponse->withJson($find);
});

//Add new course
$app->post('/tutor/editCourse', function ($request, $response) {
	$input = $request->getParsedBody();
	//Retrieve the authorization token and get the id of the active user
	$authArray = $request->getHeader('Authorization');
	$auth = implode(" ", $authArray);
	$sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
	$sth = $this->db->prepare($sql);
	$sth->bindParam(":auth", $auth);
	$sth->execute();

	//Retrieve the ID from the resulting SQL statment
	$sth->setFetchMode(PDO::FETCH_ASSOC);
	$row = $sth->fetch();
	$id = $row["id"];

	//If there was no id found, return an error
	if (empty($id)) {
		$input["Login Error"] = "The user is not logged in";
	}
	else {
		// Check to see if the course has already been added
		$sql = "SELECT * FROM `Courses Taught` WHERE course_id = :course_id";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(":course_id", $input['course_id']);
		$sth->execute();
		if($sth->rowCount() == 0) {
			$sql = "INSERT INTO `Courses Taught` (`course_id`, `tutor_id`) VALUES (:course_id, :tutor_id)";
			$sth = $this->db->prepare($sql);
			$sth->bindParam(":course_id", $input['course_id']);
			$sth->bindParam(":tutor_id", $id);
			$sth->execute();
			$input['course_id'] = $this->db->lastInsertId();
			$input['tutor_id'] = $this->db->lastInsertId();
		}
		else {
			$input['Error'] = "The tutor is already registered to teach this class.";
		}
	}
	$newResponse = $this->response->withAddedHeader("Authorization", $auth);
	return $newResponse->withJson($input);
});

//Delete a course - must test with RAW json in postman
$app->delete('/tutor/editCourse', function ($request, $response) {
	$input = $request->getParsedBody();
	//Retrieve the authorization token and get the id of the active user
	$authArray = $request->getHeader('Authorization');
	$auth = implode(" ", $authArray);
	$sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
	$sth = $this->db->prepare($sql);
	$sth->bindParam(":auth", $auth);
	$sth->execute();

	//Retrieve the ID from the resulting SQL statment
	$sth->setFetchMode(PDO::FETCH_ASSOC);
	$row = $sth->fetch();
	$id = $row["id"];

	//If there was no id found, return an error
	if (empty($id)) {
		$input["Login Error"] = "The user is not logged in";
	}
	else {
		$sql = "DELETE FROM `Courses Taught` WHERE course_id = :course_id AND tutor_id = :tutor_id";
		$sth = $this->db->prepare($sql);
		$sth->bindParam("course_id", $input['course_id']);
		$sth->bindParam("tutor_id", $id);
		$sth->execute();
	}
	$newResponse = $this->response->withAddedHeader("Authorization", $auth);
	return $newResponse->withJson($input);
});

// Edit Tutor Profile Info
$app->post('/tutor/editProfile', function  ($request, $response) {
	$authArray = $request->getHeader('Authorization');
	$input = $request->getParsedBody();
	$auth = implode(" ", $authArray);
	$sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
	$sth = $this->db->prepare($sql);
	$sth->bindParam(":auth", $auth);
	$sth->execute();
	//Retrieve the ID from the resulting SQL statment
	$sth->setFetchMode(PDO::FETCH_ASSOC);
	$row = $sth->fetch();
	$id = $row["id"];
	//If there was no id found, return an error
	if (empty($id)) {
		$input["Login Error"] = "The user is not logged in";
	}
	else {
		$sql = "UPDATE `Tutors` SET  first_name = :first_name, last_name = :last_name, email = :email, past_high_school = :past_high_school, bio = :bio WHERE tutor_id = :id";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(":first_name", $input['first_name']);
		$sth->bindParam(":last_name", $input['last_name']);
		$sth->bindParam(":email", $input['email']);
		$sth->bindParam(":past_high_school", $input['past_high_school']);
		$sth->bindParam(":bio", $input['bio']);
		$sth->bindParam(":id", $id);
		$sth->execute();
		// Update Users table as well
		$sql = "UPDATE `Users` SET  first_name = :first_name, last_name = :last_name, email = :email WHERE id = :id";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(":first_name", $input['first_name']);
		$sth->bindParam(":last_name", $input['last_name']);
		$sth->bindParam(":email", $input['email']);
		$sth->bindParam(":id", $id);
		$sth->execute();
	}
	$newResponse = $this->response->withAddedHeader("Authorization", $auth);
	return $newResponse->withJson($input);
});

// Edit Student Profile Info
$app->post('/student/editProfile', function  ($request, $response) {
	$authArray = $request->getHeader('Authorization');
	$input = $request->getParsedBody();
	$auth = implode(" ", $authArray);
	$sql = "SELECT id FROM `Web Sessions` WHERE authorization = :auth";
	$sth = $this->db->prepare($sql);
	$sth->bindParam(":auth", $auth);
	$sth->execute();
	//Retrieve the ID from the resulting SQL statment
	$sth->setFetchMode(PDO::FETCH_ASSOC);
	$row = $sth->fetch();
	$id = $row["id"];
	//If there was no id found, return an error
	if (empty($id)) {
		$input["Login Error"] = "The user is not logged in";
	}
	else {
		$sql = "UPDATE `Students` SET  first_name = :first_name, last_name = :last_name, email = :email, high_school = :high_school, bio = :bio, graduation_year = :graduation_year WHERE student_id = :id";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(":first_name", $input['first_name']);
		$sth->bindParam(":last_name", $input['last_name']);
		$sth->bindParam(":email", $input['email']);
		$sth->bindParam(":high_school", $input['high_school']);
		$sth->bindParam(":bio", $input['bio']);
		$sth->bindParam(":graduation_year", $input['graduation_year']);
		$sth->bindParam(":id", $id);
		$sth->execute();
		// Update the Users table as well
		$sql = "UPDATE `Users` SET  first_name = :first_name, last_name = :last_name, email = :email WHERE id = :id";
		$sth = $this->db->prepare($sql);
		$sth->bindParam(":first_name", $input['first_name']);
		$sth->bindParam(":last_name", $input['last_name']);
		$sth->bindParam(":email", $input['email']);
		$sth->bindParam(":id", $id);
		$sth->execute();
	}
	$newResponse = $this->response->withAddedHeader("Authorization", $auth);
	return $newResponse->withJson($input);
});
