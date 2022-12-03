FROM fuzzers/atheris:2.0.7-python3.9

# Build
RUN pip install pyvex archinfo

ADD ./mayhem/fuzz_irsb.py /fuzz_irsb.py

CMD ["/fuzz_irsb.py"]
