# Generated by Django 5.0.6 on 2024-05-28 07:56

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='SecurityEvent',
            fields=[
                ('uid', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('source_ip', models.CharField(max_length=15)),
                ('destination_ip', models.CharField(max_length=15)),
                ('event_type', models.CharField(max_length=50)),
                ('raw_data', models.TextField()),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
