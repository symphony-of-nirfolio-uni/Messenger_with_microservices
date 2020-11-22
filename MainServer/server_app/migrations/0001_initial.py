# Generated by Django 3.1.3 on 2020-11-09 19:20

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ChatList',
            fields=[
                ('chat_id', models.IntegerField(primary_key=True, serialize=False, unique=True)),
            ],
            options={
                'db_table': 'chat_list',
            },
        ),
        migrations.CreateModel(
            name='UserInfo',
            fields=[
                ('user_id', models.IntegerField(primary_key=True, serialize=False, unique=True)),
                ('first_name', models.CharField(max_length=100)),
                ('last_name', models.CharField(max_length=100)),
                ('user_name', models.CharField(max_length=100, unique=True)),
                ('email', models.CharField(max_length=50, unique=True)),
                ('status', models.CharField(max_length=500)),
                ('profile_pic', models.BinaryField()),
            ],
            options={
                'db_table': 'user_info',
            },
        ),
        migrations.CreateModel(
            name='Message',
            fields=[
                ('message_id', models.IntegerField(primary_key=True, serialize=False, unique=True)),
                ('message', models.CharField(max_length=10000)),
                ('time', models.DateTimeField()),
                ('chat', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='server_app.chatlist')),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='server_app.userinfo')),
            ],
            options={
                'db_table': 'messages',
            },
        ),
        migrations.AddField(
            model_name='chatlist',
            name='first_user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='first_user', to='server_app.userinfo'),
        ),
        migrations.AddField(
            model_name='chatlist',
            name='second_user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='second_user', to='server_app.userinfo'),
        ),
    ]
