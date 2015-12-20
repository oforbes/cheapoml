<?php session_start();

//global configuration
$config = [
  'is_user' => false,
  'user_id' => 0,
  'app_url' => 'http://YOUR WEB SITE/',
];

$db_config = [
  'host' => 'localhost',
  'db' => 'cheapo_mail',
  'charset' => 'utf8',
  'user' => 'root',
  'pass' => '1'
];

$action = '';
if (isset($_GET['action']) || isset($_POST['action'])) {
  $action = isset($_POST['action']) ? $_POST['action'] : $_GET['action'];
}

$read_message = null;
$messages = [];
$errors = [];
$new_message = [
  'subject' => '',
  'body' => '',
  'readers' => [],
];

if (isset($_SESSION['user_id'])) {
  $config['is_user'] = true;
  $config['user_id'] = $_SESSION['user_id'];
}



$dsn = "mysql:host={$db_config['host']};dbname={$db_config['db']};charset={$db_config['charset']}";
$opt = array(
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
);


try {
    $db = new PDO($dsn, $db_config['user'], $db_config['pass'], $opt);
} catch (PDOException $e) {
    die('Database connection fail: ' . $e->getMessage());
}

$user_list = [];
$user_full_list = [];
if ($config['is_user'] || $action == 'admin') {
  $stmt = $db->prepare('SELECT * FROM user');
  $stmt->execute();
  while ($row = $stmt->fetch(PDO::FETCH_LAZY))
  {
      $user_list[$row->id] = $row->username .'<' . (implode(' ', [$row->first_name, $row->last_name])). '>';
      $user_full_list[$row->id] = $row->username;
  }

}

$new_user_data = [
  'first_name' => '',
  'last_name' => '',
  'username' => '',
  'password' => '',
];

if ($action == 'logout') {
  session_destroy();
  header('Location: ' . $config['app_url']);
  exit();

} else if ($action == 'admin') {

  try {

    if (empty($_POST['user'])) {
      throw new Exception("Empty data");
    }

    $new_user_data = $_POST['user'];

    if (empty($new_user_data['username']) || empty($new_user_data['password'])) {
      $errors[] = 'Password and username are required';
      throw new Exception("Error Processing Request");
    }

    $new_user_data['username'] = trim($new_user_data['username']);
    $new_user_data['password'] = trim($new_user_data['password']);

    if (!preg_match('/((?=.*\d)(?=.*[A-Z])(?=.*[a-z])){8}/', $new_user_data['password'])) {
      $errors[] = 'Password ​should have at least one number and one letter, and one capital letter and are at least 8 digits long';
      throw new Exception("Error Processing Request");
    }

    if (in_array($new_user_data['username'], array_values($user_full_list))) {
        $errors[] = 'User with same username exist. Choose another one.';
        throw new Exception("Error Processing Request");
    }


    $stmt = $db->prepare('INSERT INTO `user` VALUES (NULL,:first_name,:last_name,:password,:username)');
    if(!$stmt->execute($new_user_data)) {
      $errors[] = 'Can\'t add new user.';
      throw new Exception("Error Processing Request");
    }



    header('Location: ' . $config['app_url'] . '?action=admin');
    exit();

  } catch (Exception $e) {

  }


} else if ($action == 'login') {

  try {
    if (empty($_POST['username']) || empty($_POST['password'])) {
      $errors[] = 'Password and username are required';
      throw new Exception("Error Processing Request");
    }

    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    $stmt = $db->prepare('SELECT * FROM user WHERE username = :username AND password = :password');
    $stmt->execute(['username' => $username, 'password' => $password]);
    $found_user = false;
    while ($row = $stmt->fetch(PDO::FETCH_LAZY))
    {
        $found_user = true;
        $_SESSION['user_id'] = $row->id;
    }

    if (!$found_user) {
      $errors[] = 'Username or password incorrect';
      throw new Exception("Error Processing Request");
    }

    header('Location: ' . $config['app_url'] . '?action=home');
    exit();

  } catch (Exception $e) {

  }


} else if ($action == 'message') {

  if (!$config['is_user']) {
    header('Location: ' . $config['app_url']);
    exit();
  }


  try {
    if (!isset($_GET['id'])) {
      $errors[] = 'Invalid message id';
      throw new Exception("Error Processing Request");
    }

    $message_id = $_GET['id'];

    $stmt = $db->prepare(
      'SELECT m.*, mr.id as mr_id '
       . '  FROM message as m '
       . ' INNER JOIN message_read as mr ON (mr.message_id = m.id AND mr.reader_id = :user_id) '
       . ' LEFT JOIN user as u ON (u.id = m.user_id) '
       . ' WHERE m.id = :message_id'
    );
    $stmt->execute(['user_id' => $config['user_id'], 'message_id' => $message_id]);

    while ($row = $stmt->fetch(PDO::FETCH_LAZY))
    {
        $read_message = [
          'id' => $row['id'],
          'subject' => $row['subject'],
          'body' => $row['body'],
          'mr_id' => $row['mr_id']
        ];
    }

    if (is_null($read_message)) {
      $errors[] = 'Message not found';
      throw new Exception("Error Processing Request");
    }

    $stmt = $db->prepare('UPDATE message_read set `date`= now()  WHERE id = :id');
    $stmt->execute(['id' => $read_message['mr_id']]);


  } catch (Exception $e) {

  }

} else if ($action == 'compose') {

    if (!$config['is_user']) {
      header('Location: ' . $config['app_url']);
      exit();
    }

  try {
    if (empty($_POST['message'])) {
      throw new Exception("Empty POST data");
    }

    if (isset($_POST['message'])) {
        $new_message = $_POST['message'];
    }


    if (empty($new_message['subject'])) {
      $errors[] = 'Subject is required';
      throw new Exception("Error Processing Request");
    }

    if (empty($new_message['body'])) {
      $errors[] = 'Body is required';
      throw new Exception("Error Processing Request");
    }

    if (empty($new_message['readers'])) {
      $errors[] = 'Select at least one reciever';
      throw new Exception("Error Processing Request");
    }

    $new_message['user_id'] = $config['user_id'];

    $stmt = $db->prepare("INSERT INTO message (body, subject, user_id) VALUES (:body, :subject, :user_id)");
    $stmt->bindParam(':body', $new_message['body']);
    $stmt->bindParam(':subject', $new_message['subject']);
    $stmt->bindParam(':user_id', $new_message['user_id']);
    if ($stmt->execute()){
      $lastId = $db->lastInsertId();
      //array_fill(0, count($colNames), '?'))

      #insert data to message_read

      $sql = "INSERT INTO message_read (message_id, reader_id,date) VALUES ";
      $data_to_insert = [];
      $tmp_sql_items = [];
      foreach ($new_message['readers'] as $reader_id) {
        $data_to_insert[] = $lastId;
        $data_to_insert[] = $reader_id;
        $tmp_sql_items[] = '(?, ?, NULL)';
      }

      $stmt = $db->prepare($sql . ' ' . implode(', ', $tmp_sql_items));
      $stmt->execute($data_to_insert);

    }

    header('Location: ' . $config['app_url'] . '?action=home');
    exit();

  } catch (Exception $e) {

  }


} else if ($action == 'home') {
  if (!$config['is_user']) {
    header('Location: ' . $config['app_url']);
    exit();
  }

  $stmt = $db->prepare(
    'SELECT m.*, mr.date as read_date, u.username, u.first_name, u.last_name '
     . '  FROM message as m '
     . ' INNER JOIN message_read as mr ON (mr.message_id = m.id AND mr.reader_id = :user_id) '
     . ' LEFT JOIN user as u ON (u.id = m.user_id)'
  );
  $stmt->execute(['user_id' => $config['user_id']]);

  while ($row = $stmt->fetch(PDO::FETCH_LAZY))
  {
      $messages[] = [
        'id' => $row['id'],
        'subject' => $row['subject'],
        'new' => is_null($row['read_date']),
        'username' => $row['username'],
        'fullname' => implode(' ' , [$row['first_name'], $row['lasst_name']])
      ];
  }

}


 ?><!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <meta name="description" content="">
    <meta name="author" content="">

    <title>Cheapo mail</title>

    <!-- Bootstrap core CSS -->
    <link href="./vendor/twbs/bootstrap/dist/css/bootstrap.min.css" rel="stylesheet">

    <!-- Custom styles for this template -->
    <link href="./assets/style.css" rel="stylesheet">

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
  </head>

  <body>

    <nav class="navbar navbar-inverse navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </button>
          <a class="navbar-brand" href="<?php echo $config['app_url'] ?>">Cheapo mail</a>
        </div>
        <div id="navbar" class="navbar-collapse collapse">
          <div class="navbar-form navbar-left " >
         <a href="<?php echo $config['app_url'] ?>?action=admin" class="btn btn-primary" >add user</a>
       </div>
          <?php if ($config['is_user']) { ?>
            <form class="navbar-form navbar-right">
              <a href="<?php echo $config['app_url'] ?>?action=home" class="btn btn-primary" >Dashboard</a>
              <a href="<?php echo $config['app_url'] ?>?action=compose" class="btn btn-success" >Compose</a>
            <a href="<?php echo $config['app_url'] ?>?action=logout" class="btn btn-danger" >Logout</a>

            </form>
          <?php } else { ?>
          <form method="POST" action="<?php echo $config['app_url'] ?>?action=login" class="navbar-form navbar-right">
            <div class="form-group">
              <input type="text" placeholder="Username" name="username" class="form-control">
            </div>
            <div class="form-group">
              <input type="password" placeholder="Password"  name="password" class="form-control">
            </div>
            <button type="submit" class="btn btn-success">Sign in</button>
          </form>
          <?php } ?>
        </div><!--/.navbar-collapse -->
      </div>
    </nav>

    <?php if (!empty($errors)) { ?>
      <div class="alert alert-danger" role="alert">
        <span class="glyphicon glyphicon-exclamation-sign" aria-hidden="true"></span>
        You have errors: <br />
        <ol>
          <?php foreach ($errors as $error) {
            ?><li><?php echo $error ?></li><?php
          } ?>
        </ol>
      </div>
    <?php } ?>

    <div class="jumbotron">
      <div class="container">
        <h1>Cheapo mail!</h1>
        <p>This is a cheapo maill application.</p>
      </div>
    </div>
    <?php if ($config['is_user']) { ?>
      <div class="container">
        <?php if ($action == 'home') { ?>
          <?php if (!empty($messages)) { ?>
          <table class="table table-stripped" >
            <thead>
              <tr>
                <td>subject</td>
                <td>sender</td>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($messages as $message) { ?>
                <tr >
                  <td>
                    <?php if ($message['new']){ ?><strong><?php } ?>
                    <a href="<?= $config['app_url'] ?>?action=message&id=<?= $message['id'] ?>"><?= $message['subject'] ?>
                      <?php if ($message['new']){ ?></strong><?php } ?>
                  </td>
                  <td>
                    <?php if ($message['new']){ ?><strong><?php } ?>
                    <?php echo  $message['username'], '<' , $message['fullname'], '>' ?>
                    <?php if ($message['new']){ ?></strong><?php } ?>
                  </td>
                </tr>
              <?php } ?>

            </tbody>
          </table>
          <?php } else { ?>
            You don't have any message.
            <?php } ?>
          <?php } else if ($action == 'compose') { ?>

            <form  method="POST" action="<?php echo $config['app_url'] ?>?action=compose" >
              <div class="form-group">
                <label for="input-subject">Subject</label>
                <input name="message[subject]" value="<?= $new_message['subject'] ?>" class="form-control" id="input-subject" placeholder="Subject" required>
              </div>

              <div class="form-group">
                <label for="input-body">Body</label>
                <textarea name="message[body]"
                id="input-body" placeholder="Body" required
                 class="form-control" rows="3"><?= $new_message['body'] ?></textarea>
              </div>

              <div class="form-group">
                <label>Recipients</label><br />

                <?php foreach ($user_list as $user_id => $user_title) {
                  if ($user_id == $config['user_id']) {continue;}

                   ?>
                  <label>
                     <input name="message[readers][]" value="<?= $user_id ?>"
                      type="checkbox" <?= in_array($user_id,$new_message['readers'] ) ? 'checked' :'' ?>> <?= $user_title ?>
                  </label>

                <?php } ?>
              </div>

              <button type="submit" class="btn btn-default">Submit</button>
            </form>
          <?php } else if ($action == 'message') { ?>

            <form  >
              <div class="form-group">
                <label for="input-subject">Subject</label>
                <?= $read_message['subject'] ?>
              </div>
              <div class="form-group">
                <label for="input-subject">body</label>
                <?= $read_message['body'] ?>
              </div>

            </form>
          <?php } ?>
      </div>

    </div> <!-- /container -->
    <?php } ?>

    <?php if ($action == 'admin') { ?>
        <div class="container">
          <h3>ADMIN AREA</h3>
          <form  method="POST" action="<?php echo $config['app_url'] ?>?action=admin" >
            <div class="form-group">
              <label for="input-first-name">First name</label>
              <input name="user[first_name]" value="<?= $new_user_data['first_name'] ?>"
              class="form-control" id="input-first-name" placeholder="First name" >
            </div>

            <div class="form-group">
              <label for="input-last-name">Last name</label>
              <input name="user[last_name]" value="<?= $new_user_data['last_name'] ?>"
              class="form-control" id="input-last-name" placeholder="Last name" >
            </div>

            <div class="form-group">
              <label for="input-username">Username</label>
              <input name="user[username]" value="<?= $new_user_data['username'] ?>"
              class="form-control" id="input-username" placeholder="Username" required>
            </div>

            <div class="form-group">
              <label for="input-password">Password</label>
              <input name="user[password]" value="<?= $new_user_data['password'] ?>"
              class="form-control" id="input-password" placeholder="Password" required>
            </div>

            <button type="submit" class="btn btn-default">Submit</button>
          </form>
        </div>
      <?php } ?>


    <!-- Bootstrap core JavaScript
    ================================================== -->
    <!-- Placed at the end of the document so the pages load faster -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <script>window.jQuery || document.write('<script src="../../assets/js/vendor/jquery.min.js"><\/script>')</script>
    <script src="../../dist/js/bootstrap.min.js"></script>
    <!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
    <script src="../../assets/js/ie10-viewport-bug-workaround.js"></script>
  </body>
</html>
