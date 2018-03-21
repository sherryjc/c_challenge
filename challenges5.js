var fs = require('fs');
var lineReader = require('readline');


var mathTest = function() {

   var p = 37;
   var g = 5;
   var gp = p-1;

// Select a at random from the range (0,p)
	var a = 20;
	//var ga = pow(gp, a, p)
	var ga = 55;
	console.log("a=", a, " (p-1)^a mod p = ", ga);
	
	
}
function getRandomInt(max) {
  return Math.floor(Math.random() * Math.floor(max));
}

function randomTest() {
	console.log(getRandomInt(100));
	// expected output: 0, 1 or 2

	console.log(getRandomInt(1));
	// expected output: 0

	console.log(Math.random());
	// expected output: a number between 0 and 1
	
}

var bigMathTest = function () {
	console.log("Welcome, I am starting on your computation of a ^ b mod m")
	var a = 2988348162058574136915891421498819466320163312926952423791023078876139;
	var b = 2351399303373464486466122544523690094744975233415544072992656881240319;
	var m = 10 ** 40;
	console.log("a = ", a);


	var p=0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff;
 	console.log("p = ", p);

	var g = 2;
	console.log("g = ", g);

}
randomTest()
mathTest()
bigMathTest()

