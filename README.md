8/16/2024
This is a new attempt at implementing PhotoProof [1] concepts using the Gnark library.

# Glossary
These keywords and phrases are used in both the reference paper by Naveh et al. and the Golang codebase itself. I tried to maintain similar naming convention to reduce confusion.

pk_PCD:
vk_PCD:
p_s:
s_s:

pk_PP{pk_PCD, p_s} output from Generator function
vk_PP{vk_PCD, p_s} output from Generator function 
sk_PP{s_s} output from Generator function 

# References

[1] Assa Naveh and Eran Tromer. Photoproof: Cryptographic image authentication for any set of permissible transformations. In 2016 IEEE Symposium on Security and Privacy (SP), pages 255–271, 2016.