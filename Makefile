.EXPORT_ALL_VARIABLES:
PYTHONPATH=./:$PYTHONPATH

test:
	docker build -t vcert-tests .
	docker run -it --rm --name running-vcert-tests \
	--env PYTHONPATH=$$PYTHONPATH \
	--env PYTHONUNBUFFERED=$$PYTHONUNBUFFERED \
	--env FAKE=$$FAKE \
	--env TPP_USER=$$TPP_USER \
	--env TPP_PASSWORD=$$TPP_PASSWORD \
	--env TPP_URL=$$TPP_URL \
	--env TPP_ZONE=$$TPP_ZONE \
	--env CLOUD_APIKEY=$$CLOUD_APIKEY \
	--env CLOUD_ZONE=$$CLOUD_ZONE \
	--env CLOUD_URL=$$CLOUD_URL \
	 vcert-tests

package:
	pip3 install twine setuptools wheel
	rm -rf dist/
	python3 setup.py sdist bdist_wheel

publish: package
	 twine upload dist/*
