.EXPORT_ALL_VARIABLES:
PYTHONPATH=./:$PYTHONPATH

test:
	docker build -t vcert-tests .
	docker run -it --rm --name running-vcert-tests \
	--env PYTHONPATH=$$PYTHONPATH \
	--env PYTHONUNBUFFERED=$$PYTHONUNBUFFERED \
	--env FAKE=$$FAKE \
	--env TPPUSER=$$TPPUSER \
	--env TPPPASSWORD=$$TPPPASSWORD \
	--env TPPURL=$$TPPURL \
	--env TPPZONE=$$TPPZONE \
	--env TOKEN=$$TOKEN \
	--env CLOUDZONE=$$CLOUDZONE \
	--env CLOUDURL=$$CLOUDURL \
	 vcert-tests

publish:
	rm -rf dist/
	python3 setup.py sdist bdist_wheel
	twine upload dist/*
