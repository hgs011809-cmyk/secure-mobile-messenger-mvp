FROM matrixdotorg/synapse:v1.162.0@sha256:6b84a7bbac36f080b2d2e51e0289cf1b08b349598ea44a558df38d558f2c2311
USER root
COPY candidate.py /tmp/candidate.py
RUN python -c 'import ast,hashlib,pathlib,synapse; p=pathlib.Path(synapse.__file__).parent/"storage/databases/main/censor_events.py"; original=p.read_text(); candidate=pathlib.Path("/tmp/candidate.py").read_text(); assert hashlib.sha256(original.encode()).hexdigest()=="6e995c5ddcc078f9ae099af8924ee2a2e40d2f5bf5349d148a1cfc7ad2030f2f"; old="hs.get_clock().looping_call(self._censor_redactions, Duration(minutes=5))"; new="hs.get_clock().looping_call_now(self._censor_redactions, Duration(seconds=30))"; assert candidate.count(new)==1 and candidate.replace(new,old)==original; ast.parse(candidate); p.write_text(candidate); pathlib.Path("/tmp/candidate.py").unlink()'
LABEL aside.synthetic-only="true"
