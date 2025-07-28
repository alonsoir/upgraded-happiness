# run-training-models.sh
rm -rf models/*.*
python initial_trainer_models.py --max_rows 2000000
python test_synthetic_events.py
ls -lta models