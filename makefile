target = rokkaku.py

deploy:
	@pyminifier --obfuscate-import-methods \
		--obfuscate-builtins \
		--obfuscate-classes \
		--obfuscate-functions \
		--obfuscate-variables \
		--obfuscate-builtins \
		--replacement-length=$(shell shuf -i6-10 -n1) \
		--gzip $(target) | head -n -2
