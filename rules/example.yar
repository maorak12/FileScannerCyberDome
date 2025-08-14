
rule example_contains_MZ
{
  meta:
    description = "Example rule: flags files containing the string 'MZ'"
    author = "you"
  strings:
    $mz = "MZ"
  condition:
    $mz
}
