using Base.Test
using AES

mutable struct Testcase
  key::String
  iv::String
  input::String
  output::String
  encrypt::Bool
end

function loadtests(filename::String)
  println("Loading tests from $filename")
  lines = readlines(filename)

  testcases = Testcase[]
  encrypt = true
  testcase = Testcase("", "", "", "", true)
  i = 0
  for line in lines
    i += 1
    if line == ""
      continue

    elseif ismatch(r"^#", line)
      continue

    elseif line == "[ENCRYPT]"
      encrypt = true

    elseif line == "[DECRYPT]"
      encrypt = false

    elseif ismatch(r"^KEY",line)
      x = match(r"^KEY = ([0-9A-Fa-f]+)", line)
      testcase.key = x.captures[1]

    elseif ismatch(r"^IV",line)
      x = match(r"^IV = ([0-9A-Fa-f]+)", line)
      testcase.iv = x.captures[1]

    elseif ismatch(r"^PLAINTEXT",line)
      x = match(r"^PLAINTEXT = ([0-9A-Fa-f]+)", line)
      if encrypt
        testcase.input = x.captures[1]
      else
        testcase.output = x.captures[1]
      end

    elseif ismatch(r"^CIPHERTEXT",line)
      x = match(r"^CIPHERTEXT = ([0-9A-Fa-f]+)", line)
      if encrypt
        testcase.output = x.captures[1]
      else
        testcase.input = x.captures[1]
      end

    end

    if testcase.key != "" &&
       testcase.input != "" &&
       testcase.output != ""

      testcase.encrypt = encrypt
      push!(testcases, testcase)
      testcase = Testcase("","","","",true)
    end
  end
  return testcases
end

for testfile in readdir("NIST-AES-Vectors")
  fn = identity

  if ismatch(r"^(CBC|CFB|ECB|OFB)", testfile)
    testcases = loadtests("NIST-AES-Vectors/$testfile")

    for testcase in testcases
      if ismatch(r"^CBC", testfile)
        @test AESCBC(testcase.input, testcase.key, testcase.iv, testcase.encrypt) == testcase.output
      elseif ismatch(r"^CFB", testfile)
        @test AESCFB(testcase.input, testcase.key, testcase.iv, testcase.encrypt) == testcase.output
      elseif ismatch(r"^ECB", testfile)
        @test AESECB(testcase.input, testcase.key, testcase.encrypt) == testcase.output
      elseif ismatch(r"^OFB", testfile)
        @test AESOFB(testcase.input, testcase.key, testcase.iv) == testcase.output
      end
    end
  else
    println("skipping: $testfile")
  end
end




