# train-models.sh

python advanced_trainer_v2.py \
  --input_csv normal_traffic.csv \
  --output_model models/rf_normal_behavior.joblib \
  --config_file config/training_config.json
python advanced_trainer_v2.py \
  --input_csv internal_traffic_dataset.csv \
  --output_model models/rf_internal_behavior.joblib \
  --config_file config/training_config.json
python advanced_trainer.py --max_rows 1000000

ls -lta models

