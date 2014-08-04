val hash_length = 20
val iterations = 1024

sequence user_counter

table users : { Id : int, UserName : string, PassHash : blob, PassSalt : string }
		  PRIMARY KEY (Id), CONSTRAINT UniqueUserName UNIQUE (UserName)

fun hash_pass pass salt = Pbkdf2.pkcs5_pbkdf2_hmac_sha1 hash_length iterations pass salt

fun auth_user uname pass =
    user <- oneOrNoRows (SELECT *
			 FROM users
			 WHERE users.UserName={[uname]});
    case user of
	None => return None
      | Some(user') =>
	case (hash_pass pass user'.Users.PassSalt) of
	    None => return None
	  | Some(hash) => if (Pbkdf2.eq hash user'.Users.PassHash)
			  then return (Some user'.Users.Id)
			  else return None
			  

fun add_user uname pass =
    existing <- oneOrNoRows (SELECT users.Id
			     FROM users
			     WHERE users.UserName={[uname]});
    case existing of
	Some _ => return None
      | None =>
	user_id <- nextval user_counter;
	salt' <- rand;
	let
	    val salt = show salt'
	in
	    case hash_pass pass salt of
		None => return None
	      | Some(hash) =>
		dml (INSERT INTO users (Id, UserName, PassHash, PassSalt)
		     VALUES ({[user_id]}, {[uname]}, {[hash]}, {[salt]}));
		return (Some user_id)
	end
