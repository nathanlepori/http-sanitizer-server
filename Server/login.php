<?php
header("Access-Control-Allow-Origin: *");
	?>


 <link rel="stylesheet" href="style.php" media="screen">

<div class="container">

    <form id="3" method="post">
        <div id="div_login">
            <h1>Login</h1>
            <div>
                <input type="text" class="textbox" id="1" name="txt_uname" placeholder="Username" />
            </div>
            <div>
                <input type="password" class="textbox" id="2" name="txt_pwd" placeholder="Password"/>
            </div>
            <div>
                <input type="submit" value="Submit" name="submit" />
            </div>
        </div>
    </form>
</div>

<?php
include "config.php";


if(isset($_POST['submit'])){

    $uname = $_POST['txt_uname'];
    $password = $_POST['txt_pwd'];

    if ($uname != "" && $password != ""){

        $sql_query = "select count(*) as cntUser from users where username='".$uname."' and password='".$password."'";
        $result = mysqli_query($con,$sql_query);
        $row = mysqli_fetch_array($result);

        $count = $row['cntUser'];

        if($count > 0){
            $_SESSION['uname'] = $uname;
            header('Location: show.php');
        }else{
            echo "Invalid username and password";
        }

    }

}
if(isset($_GET['username']))
	echo $_GET['username'];
?>