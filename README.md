8/16/2024
This is a new attempt at implementing PhotoProof [1] concepts using the Gnark library.

# Glossary
These keywords and phrases are used in both the reference paper by Naveh et al. and the Golang codebase itself. I tried to maintain similar naming convention to reduce confusion.

RGBPixel:

I:

Z: 

Proof:

pk_PCD:

vk_PCD:

p_s:

s_s:

pk_PP{pk_PCD, p_s} output from Generator function

vk_PP{vk_PCD, p_s} output from Generator function 

sk_PP{s_s} output from Generator function 

# TODO
1. Test whether an inauthentic image can be passed as authentic.
2. Create a Crop transformation circuit. What must we assert to ensure a cropping transformation is legal?
    - Naive: Check if params are legal. Use the frontend.api functions + params to crop a frontendImage_in => frontendImage_out, then assert frontendImage_in == frontendImage_out
3. Test whether an inauthentic image can be passed as authentic
4. How can we add metadata assertions?

# References

[1] Assa Naveh and Eran Tromer. Photoproof: Cryptographic image authentication for any set of permissible transformations. In 2016 IEEE Symposium on Security and Privacy (SP), pages 255–271, 2016.